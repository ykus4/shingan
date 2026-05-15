"""IOS-DYN-002: Jailbreak detection bypass via Frida."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from shingan.core.dynamic.context import DynamicContext
from shingan.core.models import Finding, Severity

logger = logging.getLogger(__name__)

_SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "jailbreak_bypass.js"

_DESCRIPTIONS = {
    "bypassed": (
        "The Frida jailbreak bypass script successfully hooked filesystem and syscall APIs "
        "used for jailbreak detection (NSFileManager, stat, access, fork). "
        "Jailbreak detection can be circumvented with a userland hook, meaning the app "
        "will run normally on a jailbroken device even when it should refuse to."
    ),
    "resistant": (
        "The bypass script ran but no jailbreak detection hooks were triggered, or the "
        "app uses detection methods that are not intercepted by userland hooks "
        "(e.g. kernel-level checks, code integrity verification)."
    ),
    "error": (
        "The jailbreak bypass script encountered an error. "
        "The result is inconclusive — manual testing is recommended."
    ),
    "unavailable": (
        "frida is not installed. Install it with: "
        "pip install 'shingan[dynamic]' or uv add frida"
    ),
}

_RECOMMENDATIONS = {
    "bypassed": (
        "Strengthen jailbreak detection by combining multiple signals: "
        "kernel-level checks (e.g. kSecAttrAccessGroupToken entitlement test), "
        "ObjC class absence checks (Cydia, Substrate), and file system checks. "
        "Consider using a commercial RASP SDK that is harder to hook at the userland layer."
    ),
    "resistant": "No action required. Jailbreak detection appears to be robust.",
    "error": "Run `shingan scan --dynamic` again; if the error persists, test manually.",
    "unavailable": "Install frida to enable dynamic jailbreak bypass testing.",
}


def check(ctx: DynamicContext) -> list[Finding]:
    """IOS-DYN-002: Attempt jailbreak detection bypass via Frida script injection."""
    script_src = _SCRIPT_PATH.read_text(encoding="utf-8")
    try:
        session = ctx.attach()
    except Exception as exc:
        logger.debug("IOS-DYN-002: attach failed: %s", exc)
        return [_make_finding("error", {"error": str(exc)})]

    result_holder: dict = {}
    done = threading.Event()

    def on_message(message: dict, _data: object) -> None:
        if message.get("type") == "send":
            result_holder.update(message.get("payload", {}))
            done.set()

    try:
        script = session.create_script(script_src)
        script.on("message", on_message)
        script.load()
        done.wait(timeout=ctx.timeout)
        script.unload()
    except Exception as exc:
        logger.debug("IOS-DYN-002: script error: %s", exc)
        return [_make_finding("error", {"error": str(exc)})]

    outcome = result_holder.get("outcome", "error")
    return [_make_finding(outcome, result_holder)]


def _make_finding(outcome: str, detail: dict) -> Finding:
    severity_map = {
        "bypassed": Severity.HIGH,
        "resistant": Severity.INFO,
        "error": Severity.MEDIUM,
        "unavailable": Severity.INFO,
    }
    return Finding(
        rule_id="IOS-DYN-002",
        title="Jailbreak detection bypass attempt",
        severity=severity_map.get(outcome, Severity.MEDIUM),
        description=_DESCRIPTIONS.get(outcome, ""),
        evidence=json.dumps(detail, ensure_ascii=False)[:400],
        recommendation=_RECOMMENDATIONS.get(outcome, ""),
        masvs="MASVS-RESILIENCE-1",
        extra={"source": "dynamic", "outcome": outcome},
    )
