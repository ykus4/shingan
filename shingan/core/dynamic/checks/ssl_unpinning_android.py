"""AND-DYN-001: SSL unpinning bypass via Frida (Android)."""

from __future__ import annotations

import json
import logging
import threading
from pathlib import Path

from shingan.core.dynamic.context import DynamicContext
from shingan.core.models import Finding, Severity

logger = logging.getLogger(__name__)

_SCRIPT_PATH = Path(__file__).parent.parent / "scripts" / "ssl_bypass_android.js"

_DESCRIPTIONS = {
    "bypassed": (
        "The Frida SSL unpinning script successfully overrode certificate trust. "
        "OkHttp3 CertificatePinner, TrustManager, or HostnameVerifier was hooked, "
        "meaning network traffic can be intercepted with a proxy (e.g. Burp Suite)."
    ),
    "resistant": (
        "The SSL unpinning script ran but no trust hooks were triggered during the "
        "observation window. Certificate pinning appears to be effective, or no "
        "network requests were made during the test."
    ),
    "error": (
        "The SSL unpinning script encountered an error. "
        "The result is inconclusive — manual testing is recommended."
    ),
    "unavailable": (
        "frida is not installed. Install it with: pip install 'shingan[dynamic]'"
    ),
}

_RECOMMENDATIONS = {
    "bypassed": (
        "Implement certificate pinning using OkHttp3's CertificatePinner with "
        "public key hashes (not full certificates). Ensure pinning is enforced in "
        "release builds and consider using a commercial RASP SDK."
    ),
    "resistant": "No action required. SSL pinning appears to be functioning correctly.",
    "error": "Run `shingan scan --dynamic` again; if the error persists, test manually.",
    "unavailable": "Install frida to enable dynamic SSL unpinning verification.",
}


def check(ctx: DynamicContext) -> list[Finding]:
    """AND-DYN-001: Attempt SSL unpinning bypass via Frida script injection."""
    script_src = _SCRIPT_PATH.read_text(encoding="utf-8")
    try:
        session = ctx.attach()
    except Exception as exc:
        logger.debug("AND-DYN-001: attach failed: %s", exc)
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
        logger.debug("AND-DYN-001: script error: %s", exc)
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
        rule_id="AND-DYN-001",
        title="SSL unpinning bypass attempt",
        severity=severity_map.get(outcome, Severity.MEDIUM),
        description=_DESCRIPTIONS.get(outcome, ""),
        evidence=json.dumps(detail, ensure_ascii=False)[:400],
        recommendation=_RECOMMENDATIONS.get(outcome, ""),
        masvs="MASVS-NETWORK-2",
        extra={"source": "dynamic", "outcome": outcome},
    )
