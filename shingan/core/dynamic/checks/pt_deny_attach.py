"""IOS-DYN-003: PT_DENY_ATTACH effectiveness test via LLDB."""

from __future__ import annotations

import logging
import subprocess

from shingan.core.dynamic.context import DynamicContext
from shingan.core.models import Finding, Severity

logger = logging.getLogger(__name__)

_DESCRIPTIONS = {
    "bypassed": (
        "LLDB successfully attached to the process. PT_DENY_ATTACH is absent or "
        "ineffective. A debugger can attach to the running app, enabling runtime "
        "inspection, memory dumping, and function hooking without Frida."
    ),
    "resistant": (
        "LLDB attach was refused or timed out. PT_DENY_ATTACH (or an equivalent "
        "anti-debug mechanism) is functioning correctly."
    ),
    "error": (
        "The LLDB attach attempt produced an unexpected result. "
        "Manual verification is recommended."
    ),
    "unavailable": (
        "lldb was not found in PATH. Install Xcode Command Line Tools: "
        "xcode-select --install"
    ),
}

_RECOMMENDATIONS = {
    "bypassed": (
        "Add `ptrace(PT_DENY_ATTACH, 0, 0, 0)` at the earliest point of app launch "
        "(e.g. in `main()` before UIApplicationMain). "
        "Also remove the `get-task-allow` entitlement from release builds and "
        "verify it is absent in the provisioning profile."
    ),
    "resistant": "No action required. Anti-debug protection is functioning.",
    "error": "Run `shingan scan --dynamic` again; if the error persists, test manually.",
    "unavailable": "Install Xcode to enable LLDB-based anti-debug testing.",
}


def check(ctx: DynamicContext) -> list[Finding]:
    """IOS-DYN-003: Test PT_DENY_ATTACH by attempting LLDB attach."""
    pid = _resolve_pid(ctx)
    if pid is None:
        return [
            _make_finding(
                "error", "Could not resolve PID for bundle_id — is the app running?"
            )
        ]

    result = _attempt_lldb_attach(pid, timeout=min(ctx.timeout, 15))
    return [_make_finding(result["outcome"], result["detail"])]


def _resolve_pid(ctx: DynamicContext) -> int | None:
    """Resolve the process PID via frida device.enumerate_processes()."""
    try:
        device = ctx.get_device()
        for proc in device.enumerate_processes():
            if ctx.bundle_id in proc.name or proc.name in ctx.bundle_id:
                return proc.pid
    except Exception as exc:
        logger.debug("PID resolution failed: %s", exc)
    return None


def _attempt_lldb_attach(pid: int, timeout: int = 15) -> dict:
    """Run LLDB in batch mode and parse the result."""
    try:
        result = subprocess.run(
            [
                "lldb",
                "--batch",
                "-o",
                f"process attach --pid {pid}",
                "-o",
                "thread list",
                "-o",
                "quit",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        stdout = (result.stdout + result.stderr)[:800]

        if "stopped" in stdout.lower() and "process attach" in stdout:
            return {"outcome": "bypassed", "detail": stdout}
        if any(
            kw in stdout
            for kw in [
                "ptrace: Operation not permitted",
                "error: attach failed",
                "cannot attach",
                "Permission denied",
                "error: attach exited",
            ]
        ):
            return {"outcome": "resistant", "detail": stdout}
        return {"outcome": "error", "detail": stdout}

    except FileNotFoundError:
        return {"outcome": "unavailable", "detail": "lldb not found in PATH"}
    except subprocess.TimeoutExpired:
        # Attach hung — PT_DENY_ATTACH likely triggered a signal
        return {
            "outcome": "resistant",
            "detail": "lldb attach timed out — PT_DENY_ATTACH likely effective",
        }


def _make_finding(outcome: str, detail: str) -> Finding:
    severity_map = {
        "bypassed": Severity.HIGH,
        "resistant": Severity.INFO,
        "error": Severity.MEDIUM,
        "unavailable": Severity.INFO,
    }
    return Finding(
        rule_id="IOS-DYN-003",
        title="PT_DENY_ATTACH effectiveness test",
        severity=severity_map.get(outcome, Severity.MEDIUM),
        description=_DESCRIPTIONS.get(outcome, ""),
        evidence=detail[:400],
        recommendation=_RECOMMENDATIONS.get(outcome, ""),
        masvs="MASVS-RESILIENCE-4",
        extra={"source": "dynamic", "outcome": outcome},
    )
