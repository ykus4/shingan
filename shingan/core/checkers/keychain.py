"""IOS-SEC-009: Keychain access level analysis.

Checks for weak kSecAttrAccessible* values that allow keychain items to be
accessed when the device is unlocked, backed up, or migrated — without user presence.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from shingan.core.models import Finding, Severity

# Ordered from most permissive (worst) to most restrictive (best)
WEAK_ACCESSIBLE: list[tuple[str, str, str]] = [
    (
        "kSecAttrAccessibleAlways",
        Severity.HIGH,
        "Item accessible at all times, even when device is locked. Never use for sensitive data.",
    ),
    (
        "kSecAttrAccessibleAlwaysThisDeviceOnly",
        Severity.HIGH,
        "Item accessible at all times (not transferable). Still accessible when locked.",
    ),
    (
        "kSecAttrAccessibleAfterFirstUnlock",
        Severity.MEDIUM,
        "Item accessible after first unlock until next reboot. Risk if device is seized while on.",
    ),
    (
        "kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly",
        Severity.LOW,
        "Same as AfterFirstUnlock but non-transferable. Still accessible without user presence.",
    ),
]

STRONG_ACCESSIBLE = [
    "kSecAttrAccessibleWhenUnlocked",
    "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
    "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly",
]


def _get_strings(binary_path: Path) -> set[str]:
    try:
        result = subprocess.run(
            ["strings", "-a", "-n", "5", str(binary_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return set(result.stdout.splitlines())
    except Exception:
        return set()


def check(binary_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    strings = _get_strings(binary_path)

    uses_keychain = any("SecItem" in s or "kSecAttr" in s for s in strings)
    if not uses_keychain:
        return findings  # no keychain usage, skip

    for attr, severity, description in WEAK_ACCESSIBLE:
        if any(attr in s for s in strings):
            findings.append(
                Finding(
                    rule_id="IOS-SEC-009",
                    title=f"Weak Keychain access level: {attr}",
                    severity=Severity(severity),
                    description=description,
                    evidence=attr,
                    recommendation=(
                        "Use kSecAttrAccessibleWhenUnlockedThisDeviceOnly or "
                        "kSecAttrAccessibleWhenPasscodeSetThisDeviceOnly for sensitive credentials."
                    ),
                    masvs="MASVS-STORAGE-1",
                )
            )

    has_strong = any(attr in s for attr in STRONG_ACCESSIBLE for s in strings)
    if uses_keychain and not findings and not has_strong:
        findings.append(
            Finding(
                rule_id="IOS-SEC-009",
                title="Keychain usage detected but access level not identifiable",
                severity=Severity.INFO,
                description=(
                    "The app uses Keychain APIs but the kSecAttrAccessible value could not be "
                    "determined statically. Verify access levels in source code."
                ),
                evidence="SecItem* calls found, kSecAttrAccessible* not found in string table",
                recommendation=(
                    "Explicitly set kSecAttrAccessibleWhenUnlockedThisDeviceOnly on all "
                    "SecItemAdd / SecItemUpdate calls."
                ),
                masvs="MASVS-STORAGE-1",
            )
        )

    return findings
