"""AND-META-012: Dangerous Android permissions.

Flags apps that declare dangerous or privacy-sensitive permissions in AndroidManifest.xml.
"""

from __future__ import annotations

from shingan.core.context import AndroidCheckContext
from shingan.core.models import Finding, Severity

# (permission, label, severity, rationale)
_DANGEROUS_PERMISSIONS: list[tuple[str, str, Severity, str]] = [
    (
        "android.permission.SEND_SMS",
        "Send SMS",
        Severity.HIGH,
        "Can silently send SMS messages, incurring charges and enabling phishing.",
    ),
    (
        "android.permission.READ_SMS",
        "Read SMS",
        Severity.HIGH,
        "Can read all SMS messages including OTP codes used for 2FA.",
    ),
    (
        "android.permission.RECEIVE_SMS",
        "Receive SMS",
        Severity.HIGH,
        "Can intercept incoming SMS messages including OTPs.",
    ),
    (
        "android.permission.READ_CALL_LOG",
        "Read Call Log",
        Severity.HIGH,
        "Can access the complete call history of the device.",
    ),
    (
        "android.permission.PROCESS_OUTGOING_CALLS",
        "Process Outgoing Calls",
        Severity.HIGH,
        "Can intercept, redirect, or abort outgoing phone calls.",
    ),
    (
        "android.permission.READ_CONTACTS",
        "Read Contacts",
        Severity.MEDIUM,
        "Can read the user's entire contacts database.",
    ),
    (
        "android.permission.WRITE_CONTACTS",
        "Write Contacts",
        Severity.MEDIUM,
        "Can modify or delete contacts.",
    ),
    (
        "android.permission.ACCESS_FINE_LOCATION",
        "Fine Location",
        Severity.MEDIUM,
        "Can access precise GPS location.",
    ),
    (
        "android.permission.RECORD_AUDIO",
        "Record Audio",
        Severity.MEDIUM,
        "Can record audio from the microphone.",
    ),
    (
        "android.permission.CAMERA",
        "Camera",
        Severity.MEDIUM,
        "Can capture photos and video.",
    ),
    (
        "android.permission.READ_EXTERNAL_STORAGE",
        "Read External Storage",
        Severity.LOW,
        "Can read files from shared external storage.",
    ),
    (
        "android.permission.WRITE_EXTERNAL_STORAGE",
        "Write External Storage",
        Severity.LOW,
        "Can write or delete files on shared external storage.",
    ),
    (
        "android.permission.GET_ACCOUNTS",
        "Get Accounts",
        Severity.LOW,
        "Can enumerate all accounts registered on the device.",
    ),
    (
        "android.permission.USE_BIOMETRIC",
        "Use Biometric",
        Severity.LOW,
        "Can use biometric authentication (informational — generally a good practice).",
    ),
]


def check(ctx: AndroidCheckContext) -> list[Finding]:
    findings: list[Finding] = []
    apk = ctx.apk
    if apk is None:
        return findings

    try:
        declared = set(apk.get_permissions())
    except Exception:
        return findings

    found: list[tuple[str, str, Severity]] = []
    for perm, label, severity, _rationale in _DANGEROUS_PERMISSIONS:
        if perm in declared:
            found.append((perm, label, severity))

    if not found:
        return findings

    # Group by severity to produce cleaner output
    high = [(p, lbl) for p, lbl, s in found if s == Severity.HIGH]
    medium = [(p, lbl) for p, lbl, s in found if s == Severity.MEDIUM]
    low = [(p, lbl) for p, lbl, s in found if s == Severity.LOW]

    for group, severity, label_str in [
        (high, Severity.HIGH, "high-risk"),
        (medium, Severity.MEDIUM, "medium-risk"),
        (low, Severity.LOW, "low-risk"),
    ]:
        if not group:
            continue
        evidence_lines = [f"{perm}  ({lbl})" for perm, lbl in group]
        findings.append(
            Finding(
                rule_id=f"AND-META-012-{severity.value}",
                title=f"{len(group)} {label_str} permission(s) declared",
                severity=severity,
                description=(
                    f"The app declares {len(group)} {label_str} Android permission(s). "
                    "Each permission should be justified by a clear user-facing feature. "
                    "Unnecessary permissions increase the privacy and security impact of a compromise."
                ),
                evidence="\n".join(evidence_lines),
                recommendation=(
                    "Remove permissions not required for core app functionality. "
                    "Request permissions at runtime and only when the feature is needed."
                ),
                masvs="MASVS-PLATFORM-1",
            )
        )

    return findings
