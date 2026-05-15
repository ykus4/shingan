// shingan IOS-DYN-002: Jailbreak detection bypass attempt
//
// Hooks NSFileManager, POSIX stat/access, and fork/system calls to hide
// common jailbreak indicators.
//
// Message payload: { outcome: "bypassed" | "resistant", hooked_paths: string[] }

"use strict";

const hookedPaths = [];
let bypassTriggered = false;

const JB_PATHS = [
  "/Applications/Cydia.app",
  "/Applications/blackra1n.app",
  "/Applications/FakeCarrier.app",
  "/Applications/Icy.app",
  "/Applications/IntelliScreen.app",
  "/Applications/MxTube.app",
  "/Applications/RockApp.app",
  "/Applications/SBSettings.app",
  "/Applications/WinterBoard.app",
  "/Library/MobileSubstrate/MobileSubstrate.dylib",
  "/Library/MobileSubstrate/DynamicLibraries",
  "/private/var/lib/apt",
  "/private/var/lib/cydia",
  "/private/var/mobile/Library/SBSettings/Themes",
  "/private/var/stash",
  "/usr/bin/sshd",
  "/usr/libexec/ssh-keysign",
  "/usr/sbin/sshd",
  "/etc/apt",
  "/bin/bash",
  "/.bootstrapped_electra",
  "/.installed_unc0ver",
];

function isJailbreakPath(path) {
  if (!path) return false;
  return JB_PATHS.some((p) => path.startsWith(p));
}

// --- 1. NSFileManager -fileExistsAtPath: ---
try {
  if (ObjC.available) {
    const NSFileManager = ObjC.classes.NSFileManager;
    if (NSFileManager) {
      const fileExists = NSFileManager["- fileExistsAtPath:"];
      if (fileExists) {
        Interceptor.attach(fileExists.implementation, {
          onEnter(args) {
            this.path = ObjC.Object(args[2]).toString();
          },
          onLeave(retval) {
            if (isJailbreakPath(this.path)) {
              retval.replace(ptr("0x0")); // NO
              hookedPaths.push(this.path);
              bypassTriggered = true;
            }
          },
        });
      }

      // -fileExistsAtPath:isDirectory:
      const fileExistsDir = NSFileManager["- fileExistsAtPath:isDirectory:"];
      if (fileExistsDir) {
        Interceptor.attach(fileExistsDir.implementation, {
          onEnter(args) {
            this.path = ObjC.Object(args[2]).toString();
          },
          onLeave(retval) {
            if (isJailbreakPath(this.path)) {
              retval.replace(ptr("0x0")); // NO
              hookedPaths.push(this.path + " (isDirectory)");
              bypassTriggered = true;
            }
          },
        });
      }
    }
  }
} catch (_) {}

// --- 2. POSIX stat() ---
const statPtr = Module.findExportByName(null, "stat");
if (statPtr) {
  Interceptor.attach(statPtr, {
    onEnter(args) {
      try {
        this.path = args[0].readUtf8String();
      } catch (_) {
        this.path = null;
      }
    },
    onLeave(retval) {
      if (isJailbreakPath(this.path)) {
        retval.replace(ptr("-1")); // ENOENT
        hookedPaths.push("stat:" + this.path);
        bypassTriggered = true;
      }
    },
  });
}

// --- 3. POSIX access() ---
const accessPtr = Module.findExportByName(null, "access");
if (accessPtr) {
  Interceptor.attach(accessPtr, {
    onEnter(args) {
      try {
        this.path = args[0].readUtf8String();
      } catch (_) {
        this.path = null;
      }
    },
    onLeave(retval) {
      if (isJailbreakPath(this.path)) {
        retval.replace(ptr("-1")); // EACCES
        hookedPaths.push("access:" + this.path);
        bypassTriggered = true;
      }
    },
  });
}

// --- 4. fork() / system() (used by some JB detectors to check escape) ---
const forkPtr = Module.findExportByName(null, "fork");
if (forkPtr) {
  Interceptor.attach(forkPtr, {
    onLeave(retval) {
      // Return -1 to indicate fork is not available (sandboxed)
      retval.replace(ptr("-1"));
      hookedPaths.push("fork()");
      bypassTriggered = true;
    },
  });
}

setTimeout(() => {
  send({
    outcome: bypassTriggered ? "bypassed" : "resistant",
    hooked_paths: [...new Set(hookedPaths)],
  });
}, 5000);
