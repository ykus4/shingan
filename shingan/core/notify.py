"""JIRA / Slack webhook notifications for new HIGH findings.

Configure via environment variables:
  SHINGAN_SLACK_WEBHOOK_URL  — Incoming Webhooks URL
  SHINGAN_JIRA_URL           — e.g. https://myorg.atlassian.net
  SHINGAN_JIRA_PROJECT       — project key, e.g. SEC
  SHINGAN_JIRA_EMAIL         — Atlassian account email
  SHINGAN_JIRA_API_TOKEN     — API token (not password)

Both channels are optional and independent. If the environment variable is
not set, that channel is silently skipped. Errors are logged as warnings
and never propagate to the caller.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import urllib.request
from collections.abc import Sequence

from shingan.core.models import Finding, ScanResult

logger = logging.getLogger(__name__)


def _post_json(url: str, payload: dict, *, headers: dict | None = None) -> None:
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:  # noqa: S310
        if resp.status >= 400:
            raise RuntimeError(f"HTTP {resp.status} from {url}")


def notify_slack(result: ScanResult, new_highs: Sequence[Finding]) -> None:
    """Post a Slack message listing new HIGH findings."""
    url = os.getenv("SHINGAN_SLACK_WEBHOOK_URL")
    if not url or not new_highs:
        return

    blocks: list[dict] = [
        {
            "type": "header",
            "text": {
                "type": "plain_text",
                "text": f":rotating_light: shingan — {len(new_highs)} new HIGH finding(s)",
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
    for f in new_highs:
        blocks.append(
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"• *{f.rule_id}* — {f.title}"},
            }
        )

    _post_json(url, {"blocks": blocks})


def notify_jira(result: ScanResult, new_highs: Sequence[Finding]) -> None:
    """Create a JIRA issue listing new HIGH findings (Cloud REST API v3)."""
    base = os.getenv("SHINGAN_JIRA_URL")
    project = os.getenv("SHINGAN_JIRA_PROJECT")
    email = os.getenv("SHINGAN_JIRA_EMAIL")
    token = os.getenv("SHINGAN_JIRA_API_TOKEN")

    if not all([base, project, email, token]) or not new_highs:
        return

    creds = base64.b64encode(f"{email}:{token}".encode()).decode()
    headers = {"Authorization": f"Basic {creds}"}

    body_text = "\n".join(f"- {f.rule_id}: {f.title}" for f in new_highs)
    summary = (
        f"[shingan] {len(new_highs)} new HIGH finding(s) in "
        f"{result.app_id} {result.app_version}"
    )

    # Atlassian Document Format (Cloud v3)
    adf_body = {
        "type": "doc",
        "version": 1,
        "content": [
            {
                "type": "paragraph",
                "content": [{"type": "text", "text": body_text}],
            }
        ],
    }

    payload = {
        "fields": {
            "project": {"key": project},
            "summary": summary,
            "description": adf_body,
            "issuetype": {"name": "Bug"},
            "priority": {"name": "High"},
        }
    }
    _post_json(f"{base}/rest/api/3/issue", payload, headers=headers)


def notify_all(result: ScanResult, new_highs: Sequence[Finding]) -> None:
    """Fire both Slack and JIRA notifications. Errors are logged, never raised."""
    for fn in (notify_slack, notify_jira):
        try:
            fn(result, new_highs)
        except Exception as exc:
            logger.warning("Notification failed (%s): %s", fn.__name__, exc)
