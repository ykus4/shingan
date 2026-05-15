// shingan AND-DYN-002: Root detection bypass for Android
//
// Hooks common root-detection patterns: file existence checks, Runtime.exec("su"),
// Build.TAGS, and RootBeer/SafetyNet style checks.
//
// Message payload: { outcome: "bypassed" | "resistant", hooked_calls: string[] }

"use strict";

const hookedCalls = [];
let bypassTriggered = false;

function recordHit(name) {
  if (!hookedCalls.includes(name)) hookedCalls.push(name);
  bypassTriggered = true;
}

const ROOT_PATHS = [
  "/system/app/Superuser.apk",
  "/system/xbin/su",
  "/system/bin/su",
  "/sbin/su",
  "/su/bin/su",
  "/data/local/su",
  "/data/local/bin/su",
  "/data/local/xbin/su",
  "/system/sd/xbin/su",
  "/system/bin/failsafe/su",
  "/system/usr/we-need-root/su",
  "/cache/su",
  "/system/app/SuperSU.apk",
  "/system/app/SuperSU/SuperSU.apk",
  "/system/xbin/daemonsu",
  "/system/xbin/busybox",
  "/system/bin/.ext/.su",
  "/system/bin/bstk/su",
  "/magisk",
  "/.magisk",
  "/data/adb/magisk",
  "/sbin/.magisk",
  "/sbin/magisk",
];

// --- 1. java.io.File.exists() ---
try {
  const File = Java.use("java.io.File");
  File.exists.implementation = function () {
    const path = this.getAbsolutePath();
    if (ROOT_PATHS.some((p) => path === p || path.startsWith(p))) {
      recordHit("File.exists:" + path);
      return false;
    }
    return this.exists.call(this);
  };
} catch (_) {}

// --- 2. java.io.File.canExecute() ---
try {
  const File = Java.use("java.io.File");
  File.canExecute.implementation = function () {
    const path = this.getAbsolutePath();
    if (ROOT_PATHS.some((p) => path === p)) {
      recordHit("File.canExecute:" + path);
      return false;
    }
    return this.canExecute.call(this);
  };
} catch (_) {}

// --- 3. Runtime.exec("su") ---
try {
  const Runtime = Java.use("java.lang.Runtime");
  Runtime.exec.overload("java.lang.String").implementation = function (cmd) {
    if (typeof cmd === "string" && (cmd.trim() === "su" || cmd.includes("/su"))) {
      recordHit("Runtime.exec:su");
      throw Java.use("java.io.IOException").$new("Permission denied");
    }
    return this.exec.call(this, cmd);
  };
  Runtime.exec.overload("[Ljava.lang.String;").implementation = function (cmds) {
    if (cmds && cmds.length > 0 && (cmds[0] === "su" || cmds[0].endsWith("/su"))) {
      recordHit("Runtime.exec:[su]");
      throw Java.use("java.io.IOException").$new("Permission denied");
    }
    return this.exec.call(this, cmds);
  };
} catch (_) {}

// --- 4. android.os.Build.TAGS ---
try {
  const Build = Java.use("android.os.Build");
  // Replace "test-keys" (root indicator) with "release-keys"
  const tagsField = Build.class.getDeclaredField("TAGS");
  tagsField.setAccessible(true);
  if (tagsField.get(null) && tagsField.get(null).includes("test-keys")) {
    tagsField.set(null, "release-keys");
    recordHit("Build.TAGS patched");
  }
} catch (_) {}

// --- 5. ProcessManager / which su ---
try {
  const ProcessBuilder = Java.use("java.lang.ProcessBuilder");
  ProcessBuilder.start.implementation = function () {
    const cmd = this.command().toArray();
    if (cmd && cmd.length > 0 && (cmd[0] === "which" || cmd[0].endsWith("which")) && cmd[1] === "su") {
      recordHit("ProcessBuilder:which su");
      throw Java.use("java.io.IOException").$new("Command not found");
    }
    return this.start.call(this);
  };
} catch (_) {}

setTimeout(() => {
  send({
    outcome: bypassTriggered ? "bypassed" : "resistant",
    hooked_calls: [...new Set(hookedCalls)],
  });
}, 5000);
