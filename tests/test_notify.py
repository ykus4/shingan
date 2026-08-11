"""Tests for notification dispatch."""

from __future__ import annotations

import logging

import pytest

from shingan.core.models import Severity
from shingan.core.notify import (
    NotificationError,
    notify_all,
    notify_jira,
    notify_slack,
    select_new_high_findings,
)

# ── Selecting what to notify about ────────────────────────────────────────────


def test_no_baseline_treats_everything_severe_as_new(make_result, make_finding) -> None:
    current = make_result(
        [
            make_finding("H", severity=Severity.HIGH),
            make_finding("M", severity=Severity.MEDIUM),
        ]
    )
    assert [f.rule_id for f in select_new_high_findings(current, None)] == ["H"]


def test_critical_is_included(make_result, make_finding) -> None:
    current = make_result([make_finding("C", severity=Severity.CRITICAL)])
    assert len(select_new_high_findings(current, None)) == 1


def test_low_severity_never_notifies(make_result, make_finding) -> None:
    current = make_result(
        [
            make_finding("L", severity=Severity.LOW),
            make_finding("I", severity=Severity.INFO),
        ]
    )
    assert select_new_high_findings(current, None) == []


def test_findings_already_in_baseline_are_not_new(make_result, make_finding) -> None:
    """Every HIGH used to be re-notified on every scan, duplicating JIRA issues."""
    known = make_finding("OLD", severity=Severity.HIGH, evidence="same")
    baseline = make_result([known])
    current = make_result(
        [
            make_finding("OLD", severity=Severity.HIGH, evidence="same"),
            make_finding("NEW", severity=Severity.HIGH),
        ]
    )

    assert [f.rule_id for f in select_new_high_findings(current, baseline)] == ["NEW"]


def test_identical_rescan_yields_nothing_new(make_result, make_finding) -> None:
    findings = [make_finding("H", severity=Severity.HIGH, evidence="e")]
    baseline = make_result(list(findings))
    current = make_result(list(findings))
    assert select_new_high_findings(current, baseline) == []


# ── Channel gating ────────────────────────────────────────────────────────────


def test_slack_skipped_without_webhook(
    make_result, make_finding, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.delenv("SHINGAN_SLACK_WEBHOOK_URL", raising=False)
    called: list[str] = []
    monkeypatch.setattr(
        "shingan.core.notify._post_json", lambda *a, **k: called.append("x")
    )

    notify_slack(make_result(), [make_finding(severity=Severity.HIGH)])

    assert called == []


def test_slack_skipped_with_no_findings(
    make_result, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHINGAN_SLACK_WEBHOOK_URL", "https://hooks.example.com/x")
    called: list[str] = []
    monkeypatch.setattr(
        "shingan.core.notify._post_json", lambda *a, **k: called.append("x")
    )

    notify_slack(make_result(), [])

    assert called == []


def test_slack_posts_expected_payload(
    make_result, make_finding, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHINGAN_SLACK_WEBHOOK_URL", "https://hooks.example.com/x")
    captured: dict = {}

    def fake_post(url: str, payload: dict, **_k: object) -> None:
        captured["url"] = url
        captured["payload"] = payload

    monkeypatch.setattr("shingan.core.notify._post_json", fake_post)

    notify_slack(make_result(), [make_finding("R-1", severity=Severity.HIGH)])

    assert captured["url"] == "https://hooks.example.com/x"
    assert any("R-1" in str(b) for b in captured["payload"]["blocks"])


def test_jira_requires_all_four_variables(
    make_result, make_finding, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHINGAN_JIRA_URL", "https://x.atlassian.net")
    monkeypatch.setenv("SHINGAN_JIRA_PROJECT", "SEC")
    monkeypatch.delenv("SHINGAN_JIRA_EMAIL", raising=False)
    monkeypatch.delenv("SHINGAN_JIRA_API_TOKEN", raising=False)
    called: list[str] = []
    monkeypatch.setattr(
        "shingan.core.notify._post_json", lambda *a, **k: called.append("x")
    )

    notify_jira(make_result(), [make_finding(severity=Severity.HIGH)])

    assert called == []


def test_jira_builds_issue_url(
    make_result, make_finding, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("SHINGAN_JIRA_URL", "https://x.atlassian.net/")
    monkeypatch.setenv("SHINGAN_JIRA_PROJECT", "SEC")
    monkeypatch.setenv("SHINGAN_JIRA_EMAIL", "a@b.c")
    monkeypatch.setenv("SHINGAN_JIRA_API_TOKEN", "tok")
    captured: dict = {}
    monkeypatch.setattr(
        "shingan.core.notify._post_json",
        lambda url, payload, **k: captured.update(url=url, payload=payload, kw=k),
    )

    notify_jira(make_result(), [make_finding("R-1", severity=Severity.HIGH)])

    # Trailing slash in the base URL must not double up.
    assert captured["url"] == "https://x.atlassian.net/rest/api/3/issue"
    assert captured["payload"]["fields"]["project"] == {"key": "SEC"}
    assert "Authorization" in captured["kw"]["headers"]


# ── URL scheme guard ──────────────────────────────────────────────────────────


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://host/x", "gopher://x"])
def test_non_http_schemes_are_refused(
    make_result, make_finding, monkeypatch: pytest.MonkeyPatch, url: str
) -> None:
    monkeypatch.setenv("SHINGAN_SLACK_WEBHOOK_URL", url)

    with pytest.raises(NotificationError, match="non-HTTP"):
        notify_slack(make_result(), [make_finding(severity=Severity.HIGH)])


# ── notify_all never raises ───────────────────────────────────────────────────


def test_notify_all_swallows_channel_errors(
    make_result, make_finding, monkeypatch: pytest.MonkeyPatch, caplog
) -> None:
    monkeypatch.setenv("SHINGAN_SLACK_WEBHOOK_URL", "https://hooks.example.com/x")

    def boom(*_a: object, **_k: object) -> None:
        raise NotificationError("unreachable")

    monkeypatch.setattr("shingan.core.notify._post_json", boom)

    with caplog.at_level(logging.WARNING):
        notify_all(make_result(), [make_finding(severity=Severity.HIGH)])

    assert any("Notification failed" in m for m in caplog.messages)


def test_notify_all_no_findings_is_a_noop(
    make_result, monkeypatch: pytest.MonkeyPatch
) -> None:
    called: list[str] = []
    monkeypatch.setattr(
        "shingan.core.notify.notify_slack", lambda *a: called.append("s")
    )
    monkeypatch.setattr(
        "shingan.core.notify.notify_jira", lambda *a: called.append("j")
    )

    notify_all(make_result(), [])

    assert called == []
