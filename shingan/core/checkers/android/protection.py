"""AND-RASP-005: Runtime protection checks for Android.

Checks:
  - AND-RASP-005a: Root detection present/absent
  - AND-RASP-005b: Frida/Xposed anti-tampering detection
  - AND-RASP-005c: Debugger detection
  - AND-RASP-005d: SSL pinning present/absent
"""

from __future__ import annotations

from shingan.core.context import AndroidCheckContext
from shingan.core.models import Finding, Severity

# Indicators of root detection logic
_ROOT_INDICATORS = (
    "/system/xbin/su",
    "/system/bin/su",
    "/sbin/su",
    "com.noshufou.android.su",
    "com.thirdparty.superuser",
    "eu.chainfire.supersu",
    "com.koushikdutta.superuser",
    "com.topjohnwu.magisk",
    "com.zachspong.temprootremovejb",
    "com.ramdroid.appquarantine",
    "RootBeer",
    "rootbeer",
    "isRooted",
    "isDeviceRooted",
    "checkRootMethod",
    "/data/local/bin/su",
    "/data/local/xbin/su",
    "test-keys",  # build tag check
)

# Indicators of Frida/Xposed detection
_TAMPER_INDICATORS = (
    "frida",
    "Frida",
    "FRIDA",
    "gum-js-loop",
    "frida-agent",
    "XposedBridge",
    "de.robv.android.xposed",
    "xposed",
    "Xposed",
    "substrate",
    "CydiaSubstrate",
    "com.saurik.substrate",
)

# Indicators of debugger detection
_DEBUGGER_INDICATORS = (
    "android.os.Debug.isDebuggerConnected",
    "Debug.isDebuggerConnected",
    "isDebuggerConnected",
    "android.os.Debug.waitingForDebugger",
    "ptrace",
    "PTRACE_TRACEME",
)

# Indicators of SSL pinning
_PINNING_INDICATORS = (
    "CertificatePinner",
    "certificatePinner",
    "okhttp3.CertificatePinner",
    "TrustKit",
    "trustkit",
    "OkHttpClient.Builder",
    "X509TrustManager",
    "checkServerTrusted",
    "javax.net.ssl.X509TrustManager",
    "ssl_pins",
    "pinnedCertificates",
)


def check(ctx: AndroidCheckContext) -> list[Finding]:
    findings: list[Finding] = []
    corpus = ctx.all_text

    # AND-RASP-005a: root detection
    root_hits = [s for s in corpus if any(ind in s for ind in _ROOT_INDICATORS)]
    if root_hits:
        findings.append(
            Finding(
                rule_id="AND-RASP-005a-found",
                title="Root detection logic detected",
                severity=Severity.INFO,
                description=(
                    "The app contains strings associated with root/jailbreak detection. "
                    "This is a positive security indicator — the app attempts to detect "
                    "a compromised device environment."
                ),
                evidence="\n".join(sorted(set(root_hits))[:5]),
                recommendation="Verify that root detection is comprehensive and covers Magisk hide.",
                masvs="MASVS-RESILIENCE-1",
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="AND-RASP-005a-missing",
                title="No root detection logic found",
                severity=Severity.MEDIUM,
                description=(
                    "No root or jailbreak detection logic was found in the APK. "
                    "On rooted devices, an attacker can bypass app-level security controls, "
                    "extract secrets from the app sandbox, and hook runtime methods."
                ),
                evidence="No root detection indicators found",
                recommendation=(
                    "Implement root detection using a library such as RootBeer or "
                    "Google Play Integrity API. Gracefully degrade functionality on rooted devices."
                ),
                masvs="MASVS-RESILIENCE-1",
            )
        )

    # AND-RASP-005b: Frida/Xposed detection
    tamper_hits = [s for s in corpus if any(ind in s for ind in _TAMPER_INDICATORS)]
    if tamper_hits:
        findings.append(
            Finding(
                rule_id="AND-RASP-005b-found",
                title="Frida/Xposed anti-tampering detection found",
                severity=Severity.INFO,
                description=(
                    "The app contains indicators of Frida or Xposed framework detection. "
                    "This helps prevent dynamic instrumentation and runtime hooking attacks."
                ),
                evidence="\n".join(sorted(set(tamper_hits))[:5]),
                recommendation=(
                    "Ensure detection is performed at multiple points (startup, critical operations) "
                    "and that the response is appropriate (e.g. terminate the app, not just log)."
                ),
                masvs="MASVS-RESILIENCE-4",
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="AND-RASP-005b-missing",
                title="No Frida/Xposed detection found",
                severity=Severity.LOW,
                description=(
                    "No indicators of Frida or Xposed detection were found. "
                    "Without anti-tampering checks, attackers can use dynamic instrumentation "
                    "to bypass authentication, extract secrets, and modify app behavior at runtime."
                ),
                evidence="No Frida/Xposed detection indicators found",
                recommendation=(
                    "Implement runtime integrity checks to detect instrumentation frameworks. "
                    "Consider using native code for tamper detection to increase difficulty."
                ),
                masvs="MASVS-RESILIENCE-4",
            )
        )

    # AND-RASP-005c: debugger detection
    debug_hits = [s for s in corpus if any(ind in s for ind in _DEBUGGER_INDICATORS)]
    if not debug_hits:
        findings.append(
            Finding(
                rule_id="AND-RASP-005c",
                title="No debugger detection found",
                severity=Severity.LOW,
                description=(
                    "No debugger detection logic was found in the APK. "
                    "Without this check, an attacker can attach a debugger (e.g. via ADB) "
                    "to step through sensitive operations and extract data."
                ),
                evidence="No debugger detection indicators found",
                recommendation=(
                    "Add `Debug.isDebuggerConnected()` checks at app startup and before "
                    "security-sensitive operations. Consider native `ptrace` self-attachment."
                ),
                masvs="MASVS-RESILIENCE-4",
            )
        )

    # AND-RASP-005d: SSL pinning
    pinning_hits = [s for s in corpus if any(ind in s for ind in _PINNING_INDICATORS)]
    if pinning_hits:
        findings.append(
            Finding(
                rule_id="AND-RASP-005d-found",
                title="SSL/certificate pinning indicators found",
                severity=Severity.INFO,
                description=(
                    "The app contains indicators of SSL certificate or public-key pinning. "
                    "This reduces the risk of MITM attacks by restricting trusted certificates."
                ),
                evidence="\n".join(sorted(set(pinning_hits))[:5]),
                recommendation=(
                    "Ensure pinning covers all sensitive endpoints and that backup pins are "
                    "configured to prevent lockout during certificate rotation."
                ),
                masvs="MASVS-NETWORK-2",
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="AND-RASP-005d-missing",
                title="No SSL pinning detected",
                severity=Severity.MEDIUM,
                description=(
                    "No certificate or public-key pinning was detected in the APK. "
                    "Without pinning, an attacker with a trusted CA (corporate proxy, rogue CA) "
                    "can perform MITM attacks against the app's network traffic."
                ),
                evidence="No SSL pinning indicators found",
                recommendation=(
                    "Implement certificate pinning using OkHttp's CertificatePinner, "
                    "network_security_config pin-set, or TrustKit."
                ),
                masvs="MASVS-NETWORK-2",
            )
        )

    return findings
