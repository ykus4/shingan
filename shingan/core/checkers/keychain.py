"""IOS-SEC-009: Keychain access level analysis.

Checks for weak kSecAttrAccessible* values that allow keychain items to be
accessed when the device is unlocked, backed up, or migrated — without user presence.
"""

from __future__ import annotations

from shingan.core.binary import CheckContext
from shingan.core.models import Finding, Severity

# Ordered from most permissive (worst) to most restrictive (best)
WEAK_ACCESSIBLE: list[tuple[str, Severity, str]] = [
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


def check(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    strings = ctx.strings

    uses_keychain = any("SecItem" in s or "kSecAttr" in s for s in strings)
    if not uses_keychain:
        return findings

    for attr, severity, description in WEAK_ACCESSIBLE:
        if any(attr in s for s in strings):
            findings.append(
                Finding(
                    rule_id="IOS-SEC-009",
                    title=f"Weak Keychain access level: {attr}",
                    severity=severity,
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
    if not findings and not has_strong:
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
