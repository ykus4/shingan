"""IOS-DBG-004: Debug flags, entitlements, and build configuration checks."""

from __future__ import annotations

import plistlib
import re
import subprocess
from pathlib import Path

from shingan.core.models import Finding, Severity


# Entitlements that should not appear in App Store / release builds
DANGEROUS_ENTITLEMENTS = {
    "get-task-allow": (
        Severity.HIGH,
        "Allows a debugger to attach to the process (task_for_pid). "
        "This must not be present in release builds.",
    ),
    "com.apple.security.cs.debugged": (
        Severity.HIGH,
        "Allows debugging of hardened-runtime processes.",
    ),
    "com.apple.security.cs.disable-library-validation": (
        Severity.MEDIUM,
        "Disables library validation, allowing unsigned dylibs to be injected.",
    ),
    "com.apple.security.cs.allow-unsigned-executable-memory": (
        Severity.MEDIUM,
        "Allows JIT / unsigned executable memory pages.",
    ),
    "com.apple.security.cs.allow-dyld-environment-variables": (
        Severity.MEDIUM,
        "Allows DYLD_* environment variables, which can be used for dylib injection.",
    ),
}


def _read_entitlements(binary_path: Path) -> dict:
    """Extract embedded entitlements via codesign."""
    try:
        result = subprocess.run(
            ["codesign", "-d", "--entitlements", ":-", str(binary_path)],
            capture_output=True,
            timeout=30,
        )
        raw = result.stdout
        if not raw:
            return {}
        return plistlib.loads(raw)
    except Exception:
        return {}


def _check_binary_strings_for_debug(binary_path: Path) -> list[str]:
    """Look for debug-related strings compiled into the binary."""
    try:
        result = subprocess.run(
            ["strings", "-a", "-n", "6", str(binary_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        lines = result.stdout.splitlines()
        patterns = [
            re.compile(r"\bNSLog\b"),
            re.compile(r"\bprint\("),
            re.compile(r"\bDEBUG\b"),
            re.compile(r"\b__debug\b"),
            re.compile(r"LLDB"),
            re.compile(r"lldb"),
            re.compile(r"OSLog"),
        ]
        hits = []
        for line in lines:
            for p in patterns:
                if p.search(line):
                    hits.append(line.strip()[:200])
                    break
        return list(dict.fromkeys(hits))  # deduplicate, preserve order
    except Exception:
        return []


def check(binary_path: Path, info_plist: dict) -> list[Finding]:
    findings: list[Finding] = []

    # --- 1. Dangerous entitlements ---
    entitlements = _read_entitlements(binary_path)
    for key, (severity, desc) in DANGEROUS_ENTITLEMENTS.items():
        val = entitlements.get(key)
        if val is True:
            findings.append(
                Finding(
                    rule_id="IOS-DBG-004a",
                    title=f"Dangerous entitlement present: {key}",
                    severity=severity,
                    description=desc,
                    evidence=f"{key} = true",
                    recommendation=(
                        f"Remove '{key}' from your release build entitlements. "
                        "This is typically set only in debug/development provisioning profiles."
                    ),
                )
            )

    # --- 2. Debug strings in binary ---
    debug_strings = _check_binary_strings_for_debug(binary_path)
    if debug_strings:
        findings.append(
            Finding(
                rule_id="IOS-DBG-004b",
                title="Debug/logging strings present in release binary",
                severity=Severity.LOW,
                description=(
                    f"{len(debug_strings)} debug-related string(s) found (NSLog, print, DEBUG, LLDB, etc.). "
                    "These can leak internal state and help attackers understand app flow."
                ),
                evidence="\n".join(debug_strings[:15]),
                recommendation=(
                    "Wrap debug logs in #if DEBUG preprocessor guards. "
                    "Use os_log with appropriate privacy levels for production logging."
                ),
                extra={"total_debug_strings": len(debug_strings)},
            )
        )

    # --- 3. Info.plist: NSAssertionsEnabled ---
    if info_plist.get("NSAssertionsEnabled") is True:
        findings.append(
            Finding(
                rule_id="IOS-DBG-004c",
                title="NSAssertionsEnabled is true in Info.plist",
                severity=Severity.LOW,
                description="Assertions are enabled, which may expose internal error messages.",
                evidence="NSAssertionsEnabled = true",
                recommendation="Set NSAssertionsEnabled to false or omit it in release builds.",
            )
        )

    return findings
