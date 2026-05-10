"""IOS-RASP-005: Jailbreak detection, Frida/LLDB anti-tamper, and SSL pinning indicators.

This checker looks for *presence* of protection indicators in the binary string table
and symbol table. Absence of any indicators is flagged as a gap.

Note: This is a *static* signal only. Presence of strings does not prove the protection
is effective — dynamic testing (objection/frida) is required for that.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import lief

from shingan.core.models import Finding, Severity


# --- Jailbreak detection indicators ---
JAILBREAK_STRINGS = [
    # File-system checks
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
    # Symbolic link / sandbox escape
    "/.bootstrapped_electra",
    # API-based
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
    "AFSSLPinningMode",          # AFNetworking
    "validatesDomainName",
    "SecTrustEvaluate",
    "SecCertificateCopyData",
    "kSecTrustResult",
]


def _get_strings(binary_path: Path) -> set[str]:
    try:
        result = subprocess.run(
            ["strings", "-a", "-n", "5", str(binary_path)],
            capture_output=True, text=True, timeout=60
        )
        return set(result.stdout.splitlines())
    except Exception:
        return set()


def _get_symbol_names(binary_path: Path) -> list[str]:
    try:
        binary = lief.parse(str(binary_path))
        if binary is None:
            return []
        return [sym.name for sym in binary.symbols]
    except Exception:
        return []


def check(binary_path: Path) -> list[Finding]:
    findings: list[Finding] = []

    strings = _get_strings(binary_path)
    symbols = _get_symbol_names(binary_path)
    all_text = strings | set(symbols)

    def _matches(indicators: list[str]) -> list[str]:
        found = []
        for ind in indicators:
            for text in all_text:
                if ind.lower() in text.lower():
                    found.append(text.strip()[:150])
                    break
        return found

    # --- 1. Jailbreak detection ---
    jb_hits = _matches(JAILBREAK_STRINGS)
    if jb_hits:
        findings.append(Finding(
            rule_id="IOS-RASP-005a",
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
        ))
    else:
        findings.append(Finding(
            rule_id="IOS-RASP-005a",
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
        ))

    # --- 2. Frida / instrumentation detection ---
    frida_hits = _matches(FRIDA_STRINGS)
    if frida_hits:
        findings.append(Finding(
            rule_id="IOS-RASP-005b",
            title="Frida/dynamic instrumentation detection indicators found",
            severity=Severity.INFO,
            description=(
                f"{len(frida_hits)} Frida-detection indicator(s) found. "
                "The app appears to check for Frida or similar instrumentation frameworks."
            ),
            evidence="\n".join(frida_hits[:10]),
            recommendation="Verify effectiveness with dynamic testing.",
            extra={"indicator_count": len(frida_hits)},
        ))
    else:
        findings.append(Finding(
            rule_id="IOS-RASP-005b",
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
        ))

    # --- 3. LLDB / debugger detection ---
    lldb_hits = _matches(LLDB_STRINGS)
    if lldb_hits:
        findings.append(Finding(
            rule_id="IOS-RASP-005c",
            title="Debugger detection indicators found (ptrace/sysctl)",
            severity=Severity.INFO,
            description=(
                f"{len(lldb_hits)} debugger-detection indicator(s) found (ptrace, PT_DENY_ATTACH, etc.)."
            ),
            evidence="\n".join(lldb_hits[:10]),
            recommendation="Verify that PT_DENY_ATTACH is called early in app launch.",
        ))
    else:
        findings.append(Finding(
            rule_id="IOS-RASP-005c",
            title="No debugger detection (ptrace/PT_DENY_ATTACH) found",
            severity=Severity.MEDIUM,
            description=(
                "No debugger-detection strings found. LLDB can attach to the app without resistance."
            ),
            evidence="(none found)",
            recommendation=(
                "Call ptrace(PT_DENY_ATTACH, 0, 0, 0) early in main() or application:didFinishLaunching. "
                "Note: this is a deterrent, not a complete protection."
            ),
        ))

    # --- 4. SSL Pinning ---
    ssl_hits = _matches(SSL_PINNING_STRINGS)
    if ssl_hits:
        findings.append(Finding(
            rule_id="IOS-RASP-005d",
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
        ))
    else:
        findings.append(Finding(
            rule_id="IOS-RASP-005d",
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
        ))

    return findings
