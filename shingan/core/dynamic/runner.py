"""Dynamic analysis orchestrator."""

from __future__ import annotations

import logging
from typing import Literal

from shingan.core.dynamic.checks import jailbreak_bypass, pt_deny_attach, ssl_pinning
from shingan.core.dynamic.checks import (
    root_bypass_android,
    ssl_unpinning_android,
)
from shingan.core.dynamic.context import DynamicContext
from shingan.core.models import Finding, Severity

logger = logging.getLogger(__name__)

_IOS_CHECKERS = [
    ssl_pinning.check,
    jailbreak_bypass.check,
    pt_deny_attach.check,
]

_ANDROID_CHECKERS = [
    ssl_unpinning_android.check,
    root_bypass_android.check,
]

_IOS_UNAVAILABLE = [
    ("IOS-DYN-001", "SSL pinning bypass attempt", "MASVS-NETWORK-2"),
    ("IOS-DYN-002", "Jailbreak detection bypass attempt", "MASVS-RESILIENCE-1"),
    ("IOS-DYN-003", "PT_DENY_ATTACH effectiveness test", "MASVS-RESILIENCE-4"),
]

_ANDROID_UNAVAILABLE = [
    ("AND-DYN-001", "SSL unpinning bypass attempt", "MASVS-NETWORK-2"),
    ("AND-DYN-002", "Root detection bypass attempt", "MASVS-RESILIENCE-1"),
]


def run_dynamic_checks(
    bundle_id: str,
    device_udid: str | None = None,
    timeout: int = 30,
    platform: Literal["ios", "android"] = "ios",
) -> list[Finding]:
    """Run all dynamic checks against a live app process.

    Returns unavailable-findings immediately if frida is not installed.
    Never raises — errors per checker are captured as MEDIUM findings.

    Args:
        bundle_id:   Bundle ID / package name of the target app (must be running).
        device_udid: Specific device UDID, or None for the first USB device.
        timeout:     Per-check timeout in seconds.
        platform:    "ios" or "android".
    """
    try:
        import frida  # noqa: F401
    except ImportError:
        logger.debug("frida not installed — returning unavailable findings")
        return _unavailable_findings(platform)

    checkers = _ANDROID_CHECKERS if platform == "android" else _IOS_CHECKERS

    findings: list[Finding] = []
    with DynamicContext(
        bundle_id=bundle_id, device_udid=device_udid, timeout=timeout
    ) as ctx:
        try:
            ctx.get_device()
        except Exception as exc:
            logger.debug("Device not reachable: %s", exc)
            return _device_unavailable_findings(platform, str(exc))

        for checker in checkers:
            try:
                findings += checker(ctx)
            except Exception as exc:
                logger.warning("Dynamic checker %s failed: %s", checker.__module__, exc)
                findings += _error_finding(checker.__module__, exc, platform)

    return findings


def _unavailable_findings(platform: str) -> list[Finding]:
    specs = _ANDROID_UNAVAILABLE if platform == "android" else _IOS_UNAVAILABLE
    return [
        Finding(
            rule_id=rule_id,
            title=title,
            severity=Severity.INFO,
            description=(
                "frida is not installed. Dynamic analysis requires frida. "
                "Install with: pip install 'shingan[dynamic]'"
            ),
            evidence="frida ImportError",
            recommendation="pip install 'shingan[dynamic]'",
            masvs=masvs,
            extra={"source": "dynamic", "outcome": "unavailable"},
        )
        for rule_id, title, masvs in specs
    ]


def _device_unavailable_findings(platform: str, error: str) -> list[Finding]:
    if platform == "android":
        description = (
            "Could not reach a Frida-enabled Android device or emulator. "
            "Ensure frida-server is running on the device:\n\n"
            "  # Push and start frida-server (replace <arch> with x86_64/arm64/etc.)\n"
            "  adb push frida-server /data/local/tmp/\n"
            "  adb shell 'chmod 755 /data/local/tmp/frida-server'\n"
            "  adb shell '/data/local/tmp/frida-server &'\n\n"
            "For Android emulators, the same steps apply. "
            "Run `shingan devices` to confirm the device is visible."
        )
        specs = _ANDROID_UNAVAILABLE
    else:
        description = (
            "Could not reach a Frida-enabled iOS device or simulator. "
            "Ensure the device is connected via USB and frida-server is running, "
            "or that the target simulator is booted. "
            "Run `shingan devices` to confirm the device is visible."
        )
        specs = _IOS_UNAVAILABLE

    return [
        Finding(
            rule_id=rule_id,
            title=title,
            severity=Severity.INFO,
            description=description,
            evidence=error[:300],
            recommendation="Run `shingan devices` to list reachable devices.",
            masvs=masvs,
            extra={"source": "dynamic", "outcome": "unavailable"},
        )
        for rule_id, title, masvs in specs
    ]


def _error_finding(module: str, exc: Exception, platform: str) -> list[Finding]:
    prefix = "AND" if platform == "android" else "IOS"
    return [
        Finding(
            rule_id=f"{prefix}-DYN-000",
            title=f"Dynamic checker error: {module.split('.')[-1]}",
            severity=Severity.MEDIUM,
            description=f"Dynamic checker {module} raised an unexpected exception.",
            evidence=str(exc)[:300],
            recommendation="Check device connectivity and ensure the app is running.",
            masvs="",
            extra={"source": "dynamic", "outcome": "error"},
        )
    ]
