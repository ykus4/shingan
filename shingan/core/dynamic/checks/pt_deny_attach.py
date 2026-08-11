"""IOS-DYN-003: PT_DENY_ATTACH effectiveness test via LLDB."""

from __future__ import annotations

import logging

from shingan.core.dynamic.context import DynamicContext
from shingan.core.models import Finding, Severity
from shingan.core.shell import run_command

logger = logging.getLogger(__name__)

#: Maximum characters of lldb output retained for diagnosis.
_OUTPUT_SNIPPET_LEN = 800

#: Stderr/stdout markers that mean the attach was actively refused.
_REFUSAL_MARKERS = (
    "ptrace: Operation not permitted",
    "error: attach failed",
    "cannot attach",
    "Permission denied",
    "error: attach exited",
)

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
    """Run LLDB in batch mode and classify the result."""
    result = run_command(
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
        timeout=timeout,
    )

    if result.missing:
        return {"outcome": "unavailable", "detail": "lldb not found in PATH"}
    if result.timed_out:
        # Attach hung — PT_DENY_ATTACH likely triggered a signal.
        return {
            "outcome": "resistant",
            "detail": "lldb attach timed out — PT_DENY_ATTACH likely effective",
        }

    output = (result.stdout + result.stderr)[:_OUTPUT_SNIPPET_LEN]

    if "stopped" in output.lower() and "process attach" in output:
        return {"outcome": "bypassed", "detail": output}
    if any(marker in output for marker in _REFUSAL_MARKERS):
        return {"outcome": "resistant", "detail": output}
    return {"outcome": "error", "detail": output}


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
