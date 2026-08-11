"""JIRA / Slack webhook notifications for newly-introduced HIGH findings.

Configure via environment variables:
  SHINGAN_SLACK_WEBHOOK_URL  — Incoming Webhooks URL
  SHINGAN_JIRA_URL           — e.g. https://myorg.atlassian.net
  SHINGAN_JIRA_PROJECT       — project key, e.g. SEC
  SHINGAN_JIRA_EMAIL         — Atlassian account email
  SHINGAN_JIRA_API_TOKEN     — API token (not password)

Both channels are optional and independent. If the environment variable is
not set, that channel is silently skipped. Errors are logged as warnings
and never propagate to the caller.

Callers are responsible for passing only *newly introduced* findings. Passing
every HIGH finding of every scan (as the web upload path used to) re-notifies
on each scan and creates a duplicate JIRA issue every time.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Sequence

from shingan.core.constants import HTTP_TIMEOUT
from shingan.core.models import Finding, ScanResult, Severity

logger = logging.getLogger(__name__)

#: Only ordinary web schemes may be fetched. Guards against an operator (or a
#: leaked env var) pointing a webhook at file:// or another local handler.
_ALLOWED_SCHEMES = frozenset({"http", "https"})


class NotificationError(RuntimeError):
    """Raised when a notification channel cannot be reached."""


def _post_json(url: str, payload: dict, *, headers: dict | None = None) -> None:
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in _ALLOWED_SCHEMES:
        raise NotificationError(
            f"Refusing to POST to non-HTTP(S) URL scheme: {parsed.scheme!r}"
        )

    # S310: the scheme is validated against _ALLOWED_SCHEMES immediately above.
    request = urllib.request.Request(  # noqa: S310
        url,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    try:
        # urlopen raises HTTPError for 4xx/5xx, so a status check here would be
        # unreachable; the context manager exists only to close the response.
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT):  # noqa: S310
            pass
    except urllib.error.HTTPError as exc:
        raise NotificationError(f"HTTP {exc.code} from {parsed.netloc}") from exc
    except urllib.error.URLError as exc:
        raise NotificationError(
            f"Could not reach {parsed.netloc}: {exc.reason}"
        ) from exc


def select_new_high_findings(
    current: ScanResult, baseline: ScanResult | None
) -> list[Finding]:
    """Return HIGH/CRITICAL findings in ``current`` that are absent from ``baseline``.

    With no baseline every such finding is new, which is correct for an app's
    first scan.
    """
    severe = [
        f for f in current.findings if f.severity in (Severity.CRITICAL, Severity.HIGH)
    ]
    if baseline is None:
        return severe
    known = {f.fingerprint() for f in baseline.findings}
    return [f for f in severe if f.fingerprint() not in known]


def notify_slack(result: ScanResult, new_findings: Sequence[Finding]) -> None:
    """Post a Slack message listing newly-introduced HIGH findings."""
    url = os.getenv("SHINGAN_SLACK_WEBHOOK_URL")
    if not url or not new_findings:
        return

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f":rotating_light: shingan — {len(new_findings)} new HIGH finding(s)",
            },
        },
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": f"*App:* `{result.app_id}` {result.app_version} ({result.build})",
            },
        },
    ]
    blocks.extend(
        {
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"• *{f.rule_id}* — {f.title}"},
        }
        for f in new_findings
    )

    _post_json(url, {"blocks": blocks})


def notify_jira(result: ScanResult, new_findings: Sequence[Finding]) -> None:
    """Create a JIRA issue listing newly-introduced HIGH findings (Cloud REST v3)."""
    base = os.getenv("SHINGAN_JIRA_URL")
    project = os.getenv("SHINGAN_JIRA_PROJECT")
    email = os.getenv("SHINGAN_JIRA_EMAIL")
    token = os.getenv("SHINGAN_JIRA_API_TOKEN")

    if not (base and project and email and token) or not new_findings:
        return

    creds = base64.b64encode(f"{email}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}"}

    body_text = "\n".join(f"- {f.rule_id}: {f.title}" for f in new_findings)
    summary = (
        f"[shingan] {len(new_findings)} new HIGH finding(s) in "
        f"{result.app_id} {result.app_version}"
    )

    payload = {
        "fields": {
            "project": {"key": project},
            "summary": summary,
            # Atlassian Document Format (Cloud v3)
            "description": {
                "type": "doc",
                "version": 1,
                "content": [
                    {
                        "type": "paragraph",
                        "content": [{"type": "text", "text": body_text}],
                    }
                ],
            },
            "issuetype": {"name": "Bug"},
            "priority": {"name": "High"},
        }
    }
    _post_json(f"{base.rstrip('/')}/rest/api/3/issue", payload, headers=headers)


def notify_all(result: ScanResult, new_findings: Sequence[Finding]) -> None:
    """Fire both Slack and JIRA notifications. Errors are logged, never raised."""
    if not new_findings:
        return
    for fn in (notify_slack, notify_jira):
        try:
            fn(result, new_findings)
        except NotificationError as exc:
            logger.warning("Notification failed (%s): %s", fn.__name__, exc)
        except Exception:
            logger.exception("Unexpected error in %s", fn.__name__)
