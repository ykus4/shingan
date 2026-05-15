"""AND-DYN-002: Root detection bypass via Frida (Android)."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from shingan.core.dynamic.context import DynamicContext
from shingan.core.models import Finding, Severity

logger = logging.getLogger(__name__)

_SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "root_bypass_android.js"

_DESCRIPTIONS = {
    "bypassed": (
        "The Frida root bypass script successfully hooked root detection calls "
        "(File.exists, Runtime.exec('su'), Build.TAGS). Root detection can be "
        "circumvented with userland hooks, meaning the app will run normally on a "
        "rooted device even when it should refuse to."
    ),
    "resistant": (
        "The root bypass script ran but no root-detection hooks were triggered. "
        "Root detection appears robust, or the app does not perform root detection."
    ),
    "error": (
        "The root bypass script encountered an error. "
        "The result is inconclusive — manual testing is recommended."
    ),
    "unavailable": (
        "frida is not installed. Install it with: pip install 'shingan[dynamic]'"
    ),
}

_RECOMMENDATIONS = {
    "bypassed": (
        "Strengthen root detection by combining multiple signals beyond filesystem "
        "checks: verify system partition integrity, check for Magisk/Zygisk modules, "
        "use Google Play Integrity API (replaces SafetyNet), and consider a commercial "
        "RASP SDK that operates below the Java layer."
    ),
    "resistant": "No action required. Root detection appears to be robust.",
    "error": "Run `shingan scan --dynamic` again; if the error persists, test manually.",
    "unavailable": "Install frida to enable dynamic root bypass testing.",
}


def check(ctx: DynamicContext) -> list[Finding]:
    """AND-DYN-002: Attempt root detection bypass via Frida script injection."""
    script_src = _SCRIPT_PATH.read_text(encoding="utf-8")
    try:
        session = ctx.attach()
    except Exception as exc:
        logger.debug("AND-DYN-002: attach failed: %s", exc)
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
        logger.debug("AND-DYN-002: script error: %s", exc)
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
        rule_id="AND-DYN-002",
        title="Root detection bypass attempt",
        severity=severity_map.get(outcome, Severity.MEDIUM),
        description=_DESCRIPTIONS.get(outcome, ""),
        evidence=json.dumps(detail, ensure_ascii=False)[:400],
        recommendation=_RECOMMENDATIONS.get(outcome, ""),
        masvs="MASVS-RESILIENCE-1",
        extra={"source": "dynamic", "outcome": outcome},
    )
