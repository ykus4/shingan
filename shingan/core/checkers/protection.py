"""IOS-RASP-005: Jailbreak detection, Frida/LLDB anti-tamper, and SSL pinning indicators.

This checker looks for *presence* of protection indicators in the binary string table
and symbol table. Absence of any indicators is flagged as a gap.

Note: This is a *static* signal only. Presence of strings does not prove the protection
is effective — dynamic testing (objection/frida) is required for that.
"""

from __future__ import annotations

from shingan.core.binary import CheckContext
from shingan.core.models import Finding, Severity

# --- Jailbreak detection indicators ---
JAILBREAK_STRINGS = [
    "/Applications/Cydia.app",
    "/Applications/blackra1n.app",
    "/Applications/FakeCarrier.app",
    "/Applications/Icy.app",
    "/Applications/IntelliScreen.app",
    "/Applications/MxTube.app",
    "/Applications/RockApp.app",
    "/Applications/SBSettings.app",
    "/Applications/WinterBoard.app",
    "/private/var/lib/apt",
    "/private/var/lib/cydia",
    "/private/var/mobile/Library/SBSettings/Themes",
    "/private/var/stash",
    "/private/var/tmp/cydia.log",
    "/usr/bin/sshd",
    "/usr/libexec/sftp-server",
    "/usr/sbin/sshd",
    "/etc/apt",
    "/.bootstrapped_electra",
    "cydia://",
    "MobileSubstrate",
    "substrate",
]

# --- Frida / dynamic instrumentation detection ---
FRIDA_STRINGS = [
    "frida",
    "FRIDA",
    "frida-gadget",
    "gum-js-loop",
    "frida_agent",
    "frida-server",
    "_frida_",
    "FridaGadget",
]

# --- LLDB / debugger detection ---
LLDB_STRINGS = [
    "ptrace",
    "PT_DENY_ATTACH",
    "sysctl",
    "P_TRACED",
    "isatty",
    "task_get_exception_ports",
    "getppid",
]

# --- SSL Pinning indicators ---
SSL_PINNING_STRINGS = [
    "TrustKit",
    "SSLPinning",
    "ssl_pinning",
    "certificatePinning",
    "publicKeyPinning",
    "pinnedCertificate",
    "pinnedPublicKey",
    "NSPinnedDomains",
    "AFSSLPinningMode",
    "validatesDomainName",
    "SecTrustEvaluate",
    "SecCertificateCopyData",
    "kSecTrustResult",
]


def _match_indicators(indicators: list[str], corpus: set[str]) -> list[str]:
    """Return corpus entries that contain any of the indicator strings (case-insensitive)."""
    hits: list[str] = []
    for ind in indicators:
        ind_lower = ind.lower()
        for text in corpus:
            if ind_lower in text.lower():
                hits.append(text.strip()[:150])
                break  # one corpus entry per indicator is enough
    return hits


def check(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    corpus = ctx.all_text

    # --- 1. Jailbreak detection ---
    jb_hits = _match_indicators(JAILBREAK_STRINGS, corpus)
    if jb_hits:
        findings.append(
            Finding(
                rule_id="IOS-RASP-005a-found",
                title="Jailbreak detection indicators found",
                severity=Severity.INFO,
                description=(
                    f"{len(jb_hits)} jailbreak-detection string(s) found. "
                    "The app appears to check for jailbreak artifacts. "
                    "Note: static presence does not confirm runtime effectiveness."
                ),
                evidence="\n".join(jb_hits[:10]),
                recommendation=(
                    "Verify effectiveness with dynamic testing (objection/frida). "
                    "Implement multiple independent checks at runtime."
                ),
                extra={"indicator_count": len(jb_hits)},
                masvs="MASVS-RESILIENCE-1",
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="IOS-RASP-005a-missing",
                title="No jailbreak detection indicators found",
                severity=Severity.MEDIUM,
                description=(
                    "No known jailbreak detection strings were found in the binary. "
                    "The app may be running without jailbreak awareness."
                ),
                evidence="(none found)",
                recommendation=(
                    "Add jailbreak detection if the app handles sensitive data or transactions. "
                    "Refer to OWASP MASTG MASVS-RESILIENCE for guidance."
                ),
                masvs="MASVS-RESILIENCE-1",
            )
        )

    # --- 2. Frida / instrumentation detection ---
    frida_hits = _match_indicators(FRIDA_STRINGS, corpus)
    if frida_hits:
        findings.append(
            Finding(
                rule_id="IOS-RASP-005b-found",
                title="Frida/dynamic instrumentation detection indicators found",
                severity=Severity.INFO,
                description=(
                    f"{len(frida_hits)} Frida-detection indicator(s) found. "
                    "The app appears to check for Frida or similar instrumentation frameworks."
                ),
                evidence="\n".join(frida_hits[:10]),
                recommendation="Verify effectiveness with dynamic testing.",
                extra={"indicator_count": len(frida_hits)},
                masvs="MASVS-RESILIENCE-4",
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="IOS-RASP-005b-missing",
                title="No Frida/dynamic instrumentation detection found",
                severity=Severity.MEDIUM,
                description=(
                    "No Frida detection indicators found. An attacker can attach Frida to the "
                    "process and instrument it at runtime without resistance."
                ),
                evidence="(none found)",
                recommendation=(
                    "Add Frida detection (e.g. port scan for frida-server, check for frida-gadget "
                    "in loaded libraries). Libraries like IOSSecuritySuite can help."
                ),
                masvs="MASVS-RESILIENCE-4",
            )
        )

    # --- 3. LLDB / debugger detection ---
    lldb_hits = _match_indicators(LLDB_STRINGS, corpus)
    if lldb_hits:
        findings.append(
            Finding(
                rule_id="IOS-RASP-005c-found",
                title="Debugger detection indicators found (ptrace/sysctl)",
                severity=Severity.INFO,
                description=(
                    f"{len(lldb_hits)} debugger-detection indicator(s) found "
                    "(ptrace, PT_DENY_ATTACH, etc.)."
                ),
                evidence="\n".join(lldb_hits[:10]),
                recommendation="Verify that PT_DENY_ATTACH is called early in app launch.",
                masvs="MASVS-RESILIENCE-4",
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="IOS-RASP-005c-missing",
                title="No debugger detection (ptrace/PT_DENY_ATTACH) found",
                severity=Severity.MEDIUM,
                description=(
                    "No debugger-detection strings found. "
                    "LLDB can attach to the app without resistance."
                ),
                evidence="(none found)",
                recommendation=(
                    "Call ptrace(PT_DENY_ATTACH, 0, 0, 0) early in main() or "
                    "application:didFinishLaunching. "
                    "Note: this is a deterrent, not a complete protection."
                ),
                masvs="MASVS-RESILIENCE-4",
            )
        )

    # --- 4. SSL Pinning ---
    ssl_hits = _match_indicators(SSL_PINNING_STRINGS, corpus)
    if ssl_hits:
        findings.append(
            Finding(
                rule_id="IOS-RASP-005d-found",
                title="SSL pinning indicators found",
                severity=Severity.INFO,
                description=(
                    f"{len(ssl_hits)} SSL pinning indicator(s) found. "
                    "The app appears to implement certificate or public key pinning."
                ),
                evidence="\n".join(ssl_hits[:10]),
                recommendation=(
                    "Verify with dynamic testing (objection ssl pinning disable) to confirm "
                    "the pinning cannot be trivially bypassed."
                ),
                extra={"indicator_count": len(ssl_hits)},
                masvs="MASVS-NETWORK-2",
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="IOS-RASP-005d-missing",
                title="No SSL pinning indicators found",
                severity=Severity.MEDIUM,
                description=(
                    "No SSL pinning indicators found. Network traffic can be intercepted "
                    "by installing a proxy certificate (e.g. Burp Suite, mitmproxy)."
                ),
                evidence="(none found)",
                recommendation=(
                    "Implement SSL/TLS certificate or public key pinning. "
                    "Consider TrustKit or NSPinnedDomains (iOS 14+) for implementation."
                ),
                masvs="MASVS-NETWORK-2",
            )
        )

    return findings
