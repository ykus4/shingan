"""IOS-DBG-004: Debug flags, entitlements, and build configuration checks."""

from __future__ import annotations

import logging
import plistlib
import re
import subprocess

from shingan.core.binary import CheckContext
from shingan.core.constants import EVIDENCE_DEBUG_SAMPLE
from shingan.core.models import Finding, Severity

logger = logging.getLogger(__name__)

# Entitlements that should not appear in App Store / release builds
DANGEROUS_ENTITLEMENTS: dict[str, tuple[Severity, str]] = {
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

_DEBUG_STRING_PATTERNS: list[re.Pattern] = [
    re.compile(r"\bNSLog\b"),
    re.compile(r"\bprint\("),
    re.compile(r"\bDEBUG\b"),
    re.compile(r"\b__debug\b"),
    re.compile(r"LLDB"),
    re.compile(r"lldb"),
    re.compile(r"OSLog"),
]


def _read_entitlements(binary_path) -> dict:
    """Extract embedded entitlements via codesign (macOS only)."""
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
    except Exception as exc:
        logger.debug("codesign entitlements extraction failed: %s", exc)
        return {}


def check(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []

    # --- 1. Dangerous entitlements ---
    entitlements = _read_entitlements(ctx.binary_path)
    for key, (severity, desc) in DANGEROUS_ENTITLEMENTS.items():
        if entitlements.get(key) is True:
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
                    masvs="MASVS-RESILIENCE-2",
                )
            )

    # --- 2. Debug strings in binary ---
    debug_hits: list[str] = []
    for line in ctx.strings:
        for pattern in _DEBUG_STRING_PATTERNS:
            if pattern.search(line):
                debug_hits.append(line.strip()[:200])
                break  # one match per line is enough
    # Deduplicate while preserving first-seen order
    debug_hits = list(dict.fromkeys(debug_hits))

    if debug_hits:
        findings.append(
            Finding(
                rule_id="IOS-DBG-004b",
                title="Debug/logging strings present in release binary",
                severity=Severity.LOW,
                description=(
                    f"{len(debug_hits)} debug-related string(s) found "
                    "(NSLog, print, DEBUG, LLDB, etc.). "
                    "These can leak internal state and help attackers understand app flow."
                ),
                evidence="\n".join(debug_hits[:EVIDENCE_DEBUG_SAMPLE]),
                recommendation=(
                    "Wrap debug logs in #if DEBUG preprocessor guards. "
                    "Use os_log with appropriate privacy levels for production logging."
                ),
                extra={"total_debug_strings": len(debug_hits)},
                masvs="MASVS-RESILIENCE-2",
            )
        )

    # --- 3. Info.plist: NSAssertionsEnabled ---
    if ctx.info_plist.get("NSAssertionsEnabled") is True:
        findings.append(
            Finding(
                rule_id="IOS-DBG-004c",
                title="NSAssertionsEnabled is true in Info.plist",
                severity=Severity.LOW,
                description="Assertions are enabled, which may expose internal error messages.",
                evidence="NSAssertionsEnabled = true",
                recommendation="Set NSAssertionsEnabled to false or omit it in release builds.",
                masvs="MASVS-RESILIENCE-2",
            )
        )

    return findings
