"""IOS-META-012: Over-privileged background modes and permissions."""

from __future__ import annotations

from shingan.core.models import Finding, Severity

# Background modes that warrant attention in security-sensitive apps
RISKY_BACKGROUND_MODES: dict[str, tuple[Severity, str]] = {
    "fetch": (
        Severity.INFO,
        "App can wake in the background to fetch data. Ensure fetched data is stored securely.",
    ),
    "remote-notification": (
        Severity.INFO,
        "App can wake on silent push notifications. Verify notification payload handling.",
    ),
    "voip": (
        Severity.LOW,
        "VoIP mode keeps a persistent connection. Verify the socket is properly secured.",
    ),
    "location": (
        Severity.LOW,
        "Continuous background location access. Verify location data is handled with minimal retention.",
    ),
    "bluetooth-central": (
        Severity.INFO,
        "Background Bluetooth scanning can be used for location tracking.",
    ),
    "bluetooth-peripheral": (
        Severity.INFO,
        "Background Bluetooth advertising. Verify no sensitive data is broadcast.",
    ),
    "external-accessory": (
        Severity.INFO,
        "Communicates with external accessories in the background.",
    ),
    "processing": (
        Severity.INFO,
        "Background processing tasks. Ensure tasks do not expose sensitive operations.",
    ),
}

# Privacy-sensitive usage description keys
SENSITIVE_USAGE_KEYS: list[tuple[str, str]] = [
    ("NSLocationAlwaysAndWhenInUseUsageDescription", "Always-on location access"),
    ("NSLocationAlwaysUsageDescription", "Always-on location access (legacy)"),
    ("NSCameraUsageDescription", "Camera access"),
    ("NSMicrophoneUsageDescription", "Microphone access"),
    ("NSContactsUsageDescription", "Contacts access"),
    ("NSHealthShareUsageDescription", "HealthKit read access"),
    ("NSHealthUpdateUsageDescription", "HealthKit write access"),
    ("NSFaceIDUsageDescription", "Face ID / biometric access"),
    ("NSPhotoLibraryUsageDescription", "Photo library access"),
    ("NSMotionUsageDescription", "Motion/accelerometer access"),
]


def check(info_plist: dict) -> list[Finding]:
    findings: list[Finding] = []

    # --- 1. Background modes ---
    bg_modes = info_plist.get("UIBackgroundModes", [])
    for mode in bg_modes:
        if mode in RISKY_BACKGROUND_MODES:
            severity, description = RISKY_BACKGROUND_MODES[mode]
            findings.append(
                Finding(
                    rule_id="IOS-META-012a",
                    title=f"Background mode declared: {mode}",
                    severity=severity,
                    description=description,
                    evidence=f"UIBackgroundModes contains '{mode}'",
                    recommendation=(
                        f"Ensure '{mode}' is required. Remove if not actively used. "
                        "Unnecessary background modes increase the app's attack surface."
                    ),
                    masvs="MASVS-PLATFORM-1",
                )
            )

    # --- 2. Sensitive permissions ---
    sensitive = []
    for key, label in SENSITIVE_USAGE_KEYS:
        if key in info_plist:
            sensitive.append(f"{label} ({key})")

    if sensitive:
        findings.append(
            Finding(
                rule_id="IOS-META-012b",
                title=f"Sensitive permissions declared ({len(sensitive)})",
                severity=Severity.INFO,
                description=(
                    "The following sensitive permissions are declared in Info.plist. "
                    "Verify each is necessary and the usage description is accurate."
                ),
                evidence="\n".join(sensitive),
                recommendation=(
                    "Request permissions only when needed (just-in-time). "
                    "Do not request permissions at app launch unless immediately required."
                ),
                extra={"permissions": sensitive},
                masvs="MASVS-PLATFORM-1",
            )
        )

    # --- 3. App Transport Security missing entirely ---
    if "NSAppTransportSecurity" not in info_plist:
        findings.append(
            Finding(
                rule_id="IOS-META-012c",
                title="NSAppTransportSecurity key absent from Info.plist",
                severity=Severity.INFO,
                description=(
                    "No NSAppTransportSecurity configuration found. "
                    "iOS enforces ATS by default, but explicit configuration is recommended "
                    "to make intent clear and prevent accidental exceptions."
                ),
                evidence="NSAppTransportSecurity not present",
                recommendation=(
                    "Add an explicit NSAppTransportSecurity entry even if using defaults, "
                    "to document intent and make future changes deliberate."
                ),
                masvs="MASVS-PLATFORM-1",
            )
        )

    return findings
