"""AND-META-013 / AND-SDK-015: AndroidManifest.xml security checks.

Checks:
  - android:allowBackup="true" (data backup exposure)
  - exported components without permissions (Activity/Service/Receiver/Provider)
  - minSdkVersion below a safe threshold
"""

from __future__ import annotations

from shingan.core.context import AndroidCheckContext
from shingan.core.models import Finding, Severity

# Devices running Android < 6.0 (API 23) don't support runtime permissions.
_MIN_SDK_THRESHOLD = 23


def check(ctx: AndroidCheckContext) -> list[Finding]:
    findings: list[Finding] = []
    apk = ctx.apk
    if apk is None:
        return findings

    # AND-META-013a: allowBackup
    try:
        allow_backup = apk.get_attribute_value("application", "allowBackup")
        if str(allow_backup).lower() == "true":
            findings.append(
                Finding(
                    rule_id="AND-META-013a",
                    title="android:allowBackup=true enables unencrypted ADB backup",
                    severity=Severity.MEDIUM,
                    description=(
                        'The application allows ADB backup (`android:allowBackup="true"`). '
                        "An attacker with physical or ADB access can extract the app's data directory "
                        "without root privileges using `adb backup`."
                    ),
                    evidence="android:allowBackup = true",
                    recommendation=(
                        'Set `android:allowBackup="false"` in AndroidManifest.xml, '
                        "or configure a BackupAgent to control what data is backed up."
                    ),
                    masvs="MASVS-PLATFORM-1",
                )
            )
    except Exception:
        pass

    # AND-META-013b: exported components without permission
    _check_exported_components(apk, findings)

    # AND-SDK-015: minSdkVersion too low
    try:
        min_sdk = apk.get_min_sdk_version()
        if min_sdk is not None:
            min_sdk_int = int(min_sdk)
            if min_sdk_int < _MIN_SDK_THRESHOLD:
                findings.append(
                    Finding(
                        rule_id="AND-SDK-015",
                        title=f"minSdkVersion={min_sdk_int} is below API {_MIN_SDK_THRESHOLD}",
                        severity=Severity.LOW,
                        description=(
                            f"The app supports Android API {min_sdk_int}, which predates runtime "
                            f"permissions (API {_MIN_SDK_THRESHOLD}). Devices on older Android versions "
                            "receive all permissions at install time and cannot revoke them individually."
                        ),
                        evidence=f"minSdkVersion = {min_sdk_int}",
                        recommendation=(
                            f"Raise `minSdkVersion` to at least {_MIN_SDK_THRESHOLD} "
                            "to enforce runtime permission controls."
                        ),
                        masvs="MASVS-RESILIENCE-1",
                    )
                )
    except Exception:
        pass

    return findings


def _check_exported_components(apk, findings: list[Finding]) -> None:
    """Flag exported components that declare no android:permission guard."""
    component_types = ["activity", "service", "receiver", "provider"]
    exposed: list[str] = []

    for comp_type in component_types:
        try:
            for item in apk.get_declared_permissions_details().keys():
                # Use androguard's component iteration
                pass
            # Iterate components via androguard's xml tree
            components = _get_components(apk, comp_type)
            for name, exported, has_permission in components:
                if exported and not has_permission:
                    exposed.append(f"{comp_type}: {name}")
        except Exception:
            pass

    if exposed:
        findings.append(
            Finding(
                rule_id="AND-META-013b",
                title=f"{len(exposed)} exported component(s) lack android:permission guard",
                severity=Severity.MEDIUM,
                description=(
                    "Exported Android components (Activities, Services, Receivers, Providers) "
                    "that do not declare a `android:permission` attribute can be invoked by any "
                    "app on the device, potentially leading to unauthorized access or data leakage."
                ),
                evidence="\n".join(exposed[:10]),
                recommendation=(
                    'Add `android:permission` or `android:exported="false"` to all components '
                    "that should not be publicly accessible."
                ),
                masvs="MASVS-PLATFORM-1",
            )
        )


def _get_components(apk, comp_type: str) -> list[tuple[str, bool, bool]]:
    """Return list of (name, is_exported, has_permission) for a component type."""
    result = []
    try:
        xml = apk.get_android_manifest_xml()
        app_element = xml.find("application")
        if app_element is None:
            return result
        ns = "http://schemas.android.com/apk/res/android"
        for elem in app_element.findall(comp_type):
            name = elem.get(f"{{{ns}}}name", "")
            exported_val = elem.get(f"{{{ns}}}exported", "")
            permission_val = elem.get(f"{{{ns}}}permission", "")
            is_exported = str(exported_val).lower() == "true"
            has_permission = bool(permission_val)
            result.append((name, is_exported, has_permission))
    except Exception:
        pass
    return result
