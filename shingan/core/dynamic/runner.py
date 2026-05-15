"""Dynamic analysis orchestrator."""

from __future__ import annotations

import logging

from shingan.core.dynamic.checks import jailbreak_bypass, pt_deny_attach, ssl_pinning
from shingan.core.dynamic.context import DynamicContext
from shingan.core.models import Finding, Severity

logger = logging.getLogger(__name__)

_CHECKERS = [
    ssl_pinning.check,
    jailbreak_bypass.check,
    pt_deny_attach.check,
]


def run_dynamic_checks(
    bundle_id: str,
    device_udid: str | None = None,
    timeout: int = 30,
) -> list[Finding]:
    """Run all dynamic checks against a live app process.

    Returns unavailable-findings immediately if frida is not installed.
    Never raises — errors per checker are captured as MEDIUM findings.

    Args:
        bundle_id:   CFBundleIdentifier of the target app (must be running).
        device_udid: Specific device UDID, or None for the first USB device.
        timeout:     Per-check timeout in seconds.
    """
    try:
        import frida  # noqa: F401
    except ImportError:
        logger.debug("frida not installed — returning unavailable findings")
        return _unavailable_findings()

    findings: list[Finding] = []
    with DynamicContext(
        bundle_id=bundle_id, device_udid=device_udid, timeout=timeout
    ) as ctx:
        for checker in _CHECKERS:
            try:
                findings += checker(ctx)
            except Exception as exc:
                logger.warning("Dynamic checker %s failed: %s", checker.__module__, exc)
                findings += _error_finding(checker.__module__, exc)

    return findings


def _unavailable_findings() -> list[Finding]:
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
        for rule_id, title, masvs in [
            ("IOS-DYN-001", "SSL pinning bypass attempt", "MASVS-NETWORK-2"),
            ("IOS-DYN-002", "Jailbreak detection bypass attempt", "MASVS-RESILIENCE-1"),
            ("IOS-DYN-003", "PT_DENY_ATTACH effectiveness test", "MASVS-RESILIENCE-4"),
        ]
    ]


def _error_finding(module: str, exc: Exception) -> list[Finding]:
    return [
        Finding(
            rule_id="IOS-DYN-000",
            title=f"Dynamic checker error: {module.split('.')[-1]}",
            severity=Severity.MEDIUM,
            description=f"Dynamic checker {module} raised an unexpected exception.",
            evidence=str(exc)[:300],
            recommendation="Check device connectivity and ensure the app is running.",
            masvs="",
            extra={"source": "dynamic", "outcome": "error"},
        )
    ]
