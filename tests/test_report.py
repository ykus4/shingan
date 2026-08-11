"""Tests for report rendering (JSON / SARIF / HTML / text)."""

from __future__ import annotations

import json

import pytest

from shingan.core.models import Finding, Severity
from shingan.core.report import to_html, to_json, to_sarif, to_text
from shingan.core.version import get_version


@pytest.fixture
def result(make_result):
    return make_result(
        [
            Finding(
                "IOS-ATS-003a",
                "NSAllowsArbitraryLoads is enabled",
                Severity.HIGH,
                "Allows all HTTP traffic.",
                evidence="NSAllowsArbitraryLoads = True",
                recommendation="Disable arbitrary loads.",
                masvs="MASVS-NETWORK-1",
            ),
            Finding(
                "IOS-META-012c",
                "NSAppTransportSecurity absent",
                Severity.INFO,
                "No ATS config found.",
                masvs="MASVS-PLATFORM-1",
            ),
        ],
        app_id="com.example.app",
        artifact_name="Example.ipa",
    )


# ── JSON ──────────────────────────────────────────────────────────────────────


def test_json_contains_findings(result) -> None:
    data = json.loads(to_json(result))
    assert data["app_id"] == "com.example.app"
    assert len(data["findings"]) == 2
    assert data["findings"][0]["masvs"] == "MASVS-NETWORK-1"


def test_json_is_valid_utf8_without_escapes(make_result, make_finding) -> None:
    r = make_result([make_finding("R", title="日本語タイトル")])
    assert "日本語タイトル" in to_json(r)


# ── SARIF ─────────────────────────────────────────────────────────────────────


def test_sarif_structure(result) -> None:
    data = json.loads(to_sarif(result))
    assert data["version"] == "2.1.0"
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "shingan"
    assert len(run["results"]) == 2


def test_sarif_version_tracks_the_package(result) -> None:
    """The driver version used to be hardcoded and had drifted from pyproject."""
    data = json.loads(to_sarif(result))
    assert data["runs"][0]["tool"]["driver"]["version"] == get_version()


def test_sarif_levels(make_result, make_finding) -> None:
    r = make_result(
        [
            make_finding("C", severity=Severity.CRITICAL),
            make_finding("H", severity=Severity.HIGH),
            make_finding("M", severity=Severity.MEDIUM),
            make_finding("L", severity=Severity.LOW),
            make_finding("I", severity=Severity.INFO),
        ]
    )
    levels = {
        res["ruleId"]: res["level"]
        for res in json.loads(to_sarif(r))["runs"][0]["results"]
    }
    assert levels == {
        "C": "error",
        "H": "error",
        "M": "warning",
        "L": "note",
        "I": "none",
    }


def test_sarif_rank_distinguishes_critical_from_high(make_result, make_finding) -> None:
    """SARIF has no 'critical' level, so rank carries the distinction."""
    r = make_result(
        [
            make_finding("C", severity=Severity.CRITICAL),
            make_finding("H", severity=Severity.HIGH),
        ]
    )
    ranks = {
        res["ruleId"]: res["rank"]
        for res in json.loads(to_sarif(r))["runs"][0]["results"]
    }
    assert ranks["C"] > ranks["H"]


def test_sarif_deduplicates_rules(make_result, make_finding) -> None:
    r = make_result(
        [make_finding("SAME", evidence="a"), make_finding("SAME", evidence="b")]
    )
    run = json.loads(to_sarif(r))["runs"][0]
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 2


def test_sarif_uses_artifact_name(result) -> None:
    data = json.loads(to_sarif(result))
    loc = data["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "Example.ipa"


def test_sarif_empty_result(make_result) -> None:
    data = json.loads(to_sarif(make_result([])))
    assert data["runs"][0]["results"] == []


# ── HTML ──────────────────────────────────────────────────────────────────────


def test_html_english(result) -> None:
    html = to_html(result, lang="en")
    assert "Findings" in html
    assert "Recommendation" in html
    assert "MASVS: MASVS-NETWORK-1" in html
    assert 'lang="en"' in html


def test_html_japanese(result) -> None:
    html = to_html(result, lang="ja")
    assert "検出結果" in html
    assert "推奨事項" in html
    assert 'lang="ja"' in html


def test_html_unknown_language_falls_back_to_english(result) -> None:
    assert "Findings" in to_html(result, lang="kl")


def test_html_diff_badges(result) -> None:
    fp = result.findings[0].fingerprint()
    assert "NEW" in to_html(result, diff_new={fp}, lang="en")


def test_html_escapes_injected_markup(make_result, make_finding) -> None:
    r = make_result([make_finding("R", title="<script>alert(1)</script>")])
    html = to_html(r)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


# ── Text ──────────────────────────────────────────────────────────────────────


def test_text_report_is_not_empty(result) -> None:
    text = to_text(result)
    assert text.strip()
    assert "shingan report" in text


def test_text_report_lists_every_finding(result) -> None:
    text = to_text(result)
    for finding in result.findings:
        assert finding.rule_id in text


def test_text_report_includes_summary_counts(result) -> None:
    text = to_text(result)
    assert "high" in text
    assert "total" in text


def test_text_report_orders_by_severity(make_result, make_finding) -> None:
    r = make_result(
        [
            make_finding("LOW-1", severity=Severity.LOW),
            make_finding("CRIT-1", severity=Severity.CRITICAL),
        ]
    )
    text = to_text(r)
    assert text.index("CRIT-1") < text.index("LOW-1")


def test_text_report_with_no_findings(make_result) -> None:
    assert "(none)" in to_text(make_result([]))
