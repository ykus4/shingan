// shingan AND-DYN-001: SSL unpinning bypass for Android
//
// Hooks OkHttp3 CertificatePinner, javax.net.ssl.TrustManager, and
// HostnameVerifier to force certificate trust.
//
// Message payload: { outcome: "bypassed" | "resistant", hooks_hit: string[] }

"use strict";

const hooksHit = [];
let bypassTriggered = false;

function recordHit(name) {
  if (!hooksHit.includes(name)) hooksHit.push(name);
  bypassTriggered = true;
}

// --- 1. OkHttp3 CertificatePinner.check() ---
try {
  const CertificatePinner = Java.use("okhttp3.CertificatePinner");
  CertificatePinner.check.overload("java.lang.String", "java.util.List").implementation = function (hostname, peerCertificates) {
    recordHit("OkHttp3.CertificatePinner.check");
    // Return without throwing = bypass
  };
  CertificatePinner.check.overload("java.lang.String", "[Ljava.security.cert.Certificate;").implementation = function (hostname, certs) {
    recordHit("OkHttp3.CertificatePinner.check(certs)");
  };
} catch (_) {}

// --- 2. javax.net.ssl.X509TrustManager ---
try {
  const X509TrustManager = Java.use("javax.net.ssl.X509TrustManager");
  // Hook all classes that implement X509TrustManager dynamically
  Java.enumerateLoadedClasses({
    onMatch: function (className) {
      try {
        const cls = Java.use(className);
        const iface = Java.use("javax.net.ssl.X509TrustManager").class;
        if (cls.class.getInterfaces().some((i) => i.equals(iface))) {
          try {
            cls.checkServerTrusted.overload(
              "[Ljava.security.cert.X509Certificate;",
              "java.lang.String"
            ).implementation = function () {
              recordHit("X509TrustManager.checkServerTrusted:" + className);
            };
          } catch (_) {}
          try {
            cls.checkClientTrusted.overload(
              "[Ljava.security.cert.X509Certificate;",
              "java.lang.String"
            ).implementation = function () {
              recordHit("X509TrustManager.checkClientTrusted:" + className);
            };
          } catch (_) {}
        }
      } catch (_) {}
    },
    onComplete: function () {},
  });
} catch (_) {}

// --- 3. HostnameVerifier ---
try {
  const HostnameVerifier = Java.use("javax.net.ssl.HostnameVerifier");
  Java.enumerateLoadedClasses({
    onMatch: function (className) {
      try {
        const cls = Java.use(className);
        const iface = HostnameVerifier.class;
        if (cls.class.getInterfaces().some((i) => i.equals(iface))) {
          try {
            cls.verify.overload("java.lang.String", "javax.net.ssl.SSLSession").implementation = function () {
              recordHit("HostnameVerifier.verify:" + className);
              return true;
            };
          } catch (_) {}
        }
      } catch (_) {}
    },
    onComplete: function () {},
  });
} catch (_) {}

// --- 4. TrustManagerImpl (Conscrypt / Android internal) ---
try {
  const TrustManagerImpl = Java.use("com.android.org.conscrypt.TrustManagerImpl");
  TrustManagerImpl.verifyChain.implementation = function (untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
    recordHit("Conscrypt.TrustManagerImpl.verifyChain");
    return untrustedChain;
  };
} catch (_) {}

// Report after 5s
setTimeout(() => {
  send({
    outcome: bypassTriggered ? "bypassed" : "resistant",
    hooks_hit: hooksHit,
  });
}, 5000);
