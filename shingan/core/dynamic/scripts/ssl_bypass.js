// shingan IOS-DYN-001: SSL Pinning bypass attempt
//
// Hooks SecTrustEvaluateWithError, SecTrustEvaluate, and TrustKit to force
// certificate trust. Reports outcome after observing network activity.
//
// Message payload: { outcome: "bypassed" | "resistant", hooks_hit: string[] }

"use strict";

const hooksHit = [];
let bypassTriggered = false;

// --- 1. SecTrustEvaluateWithError (iOS 12+) ---
const secTrustWithError = Module.findExportByName(
  "Security",
  "SecTrustEvaluateWithError"
);
if (secTrustWithError) {
  Interceptor.attach(secTrustWithError, {
    onLeave(retval) {
      retval.replace(ptr("0x1")); // kSecTrustResultProceed
      if (!hooksHit.includes("SecTrustEvaluateWithError")) {
        hooksHit.push("SecTrustEvaluateWithError");
      }
      bypassTriggered = true;
    },
  });
}

// --- 2. SecTrustEvaluate (legacy, pre-iOS 12 fallback) ---
const secTrust = Module.findExportByName("Security", "SecTrustEvaluate");
if (secTrust) {
  Interceptor.attach(secTrust, {
    onEnter(args) {
      // args[1] = SecTrustResultType *result pointer
      this.resultPtr = args[1];
    },
    onLeave(retval) {
      if (this.resultPtr && !this.resultPtr.isNull()) {
        // Write kSecTrustResultProceed (1) into the result pointer
        this.resultPtr.writeU32(1);
      }
      retval.replace(ptr("0x0")); // errSecSuccess
      if (!hooksHit.includes("SecTrustEvaluate")) {
        hooksHit.push("SecTrustEvaluate");
      }
      bypassTriggered = true;
    },
  });
}

// --- 3. TrustKit (if present) ---
try {
  if (ObjC.available) {
    const TSKPinningValidator = ObjC.classes.TSKPinningValidator;
    if (TSKPinningValidator) {
      const method =
        TSKPinningValidator["+ shouldAllowConnection:forHostname:"];
      if (method) {
        Interceptor.attach(method.implementation, {
          onLeave(retval) {
            retval.replace(ptr("0x1")); // YES
            if (!hooksHit.includes("TSKPinningValidator")) {
              hooksHit.push("TSKPinningValidator");
            }
            bypassTriggered = true;
          },
        });
      }
    }
  }
} catch (_) {}

// --- 4. NSURLSession didReceiveChallenge delegate ---
try {
  if (ObjC.available) {
    const NSURLSession = ObjC.classes.NSURLSession;
    if (NSURLSession) {
      // Hook URLSession:didReceiveChallenge:completionHandler: in all delegates
      // by intercepting the CFNetwork-level trust evaluation instead (covered above)
    }
  }
} catch (_) {}

// Report after observing traffic for 5 seconds
setTimeout(() => {
  send({
    outcome: bypassTriggered ? "bypassed" : "resistant",
    hooks_hit: hooksHit,
  });
}, 5000);
