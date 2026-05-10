"""Unit tests for individual checkers using synthetic inputs."""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

from shingan.core.checkers import ats
from shingan.core.checkers.metadata import check as check_metadata
from shingan.core.checkers.secrets import _shannon_entropy
from shingan.core.diff import compare
from shingan.core.models import Finding, ScanResult, Severity
from shingan.core.suppression import Suppression, SuppressionStore
from shingan.core.report import to_html, to_json, to_sarif


# ── ATS checker ───────────────────────────────────────────────────────────────


def test_ats_clean():
    findings = ats.check({})
    assert findings == []


def test_ats_arbitrary_loads():
    plist = {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}
    findings = ats.check(plist)
    assert any(f.rule_id == "IOS-ATS-003a" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_ats_arbitrary_loads_false():
    plist = {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False}}
    findings = ats.check(plist)
    assert not any(f.rule_id == "IOS-ATS-003a" for f in findings)


def test_ats_domain_http_exception():
    plist = {
        "NSAppTransportSecurity": {
            "NSExceptionDomains": {
                "example.com": {"NSExceptionAllowsInsecureHTTPLoads": True}
            }
        }
    }
    findings = ats.check(plist)
    assert any(f.rule_id == "IOS-ATS-003e" for f in findings)
    assert any("example.com" in f.title for f in findings)


def test_ats_weak_tls():
    plist = {
        "NSAppTransportSecurity": {
            "NSExceptionDomains": {
                "legacy.example.com": {"NSExceptionMinimumTLSVersion": "TLSv1.0"}
            }
        }
    }
    findings = ats.check(plist)
    assert any(f.rule_id == "IOS-ATS-003f" for f in findings)


def test_ats_file_sharing():
    findings = ats.check({"UIFileSharingEnabled": True})
    assert any(f.rule_id == "IOS-ATS-003g" for f in findings)


def test_ats_large_query_schemes():
    schemes = [f"scheme{i}" for i in range(15)]
    findings = ats.check({"LSApplicationQueriesSchemes": schemes})
    assert any(f.rule_id == "IOS-ATS-003h" for f in findings)


def test_ats_small_query_schemes_no_finding():
    schemes = [f"scheme{i}" for i in range(5)]
    findings = ats.check({"LSApplicationQueriesSchemes": schemes})
    assert not any(f.rule_id == "IOS-ATS-003h" for f in findings)


# ── Entropy ───────────────────────────────────────────────────────────────────


def test_entropy_low_for_repeated():
    assert _shannon_entropy("aaaaaaaaaa") < 1.0


def test_entropy_high_for_random():
    # A base64-like string should have high entropy
    s = "aB3xQ9mKvP2nLwRjTyUoIeWsZdHfCgA1"
    assert _shannon_entropy(s) > 4.0


# ── Diff ─────────────────────────────────────────────────────────────────────


def _make_result(findings: list[Finding]) -> ScanResult:
    r = ScanResult(
        app_id="com.example", app_version="1.0", build="1", ipa_name="test.ipa"
    )
    r.findings = findings
    return r


def _finding(rule_id: str, evidence: str = "") -> Finding:
    return Finding(
        rule_id=rule_id,
        title=rule_id,
        severity=Severity.HIGH,
        description="",
        evidence=evidence,
    )


def test_diff_new():
    baseline = _make_result([_finding("IOS-ATS-003a")])
    current = _make_result(
        [
            _finding("IOS-ATS-003a"),
            _finding("IOS-SEC-002-aws_key", "AKIAIOSFODNN7EXAMPLE"),
        ]
    )
    diff = compare(baseline, current)
    assert len(diff.new) == 1
    assert diff.new[0].rule_id == "IOS-SEC-002-aws_key"
    assert len(diff.fixed) == 0
    assert len(diff.persisted) == 1


def test_diff_fixed():
    baseline = _make_result([_finding("IOS-ATS-003a"), _finding("IOS-DBG-004a")])
    current = _make_result([_finding("IOS-ATS-003a")])
    diff = compare(baseline, current)
    assert len(diff.fixed) == 1
    assert diff.fixed[0].rule_id == "IOS-DBG-004a"
    assert len(diff.new) == 0


def test_diff_empty():
    baseline = _make_result([])
    current = _make_result([])
    diff = compare(baseline, current)
    assert diff.new == []
    assert diff.fixed == []
    assert diff.persisted == []


# ── Models ────────────────────────────────────────────────────────────────────


def test_scan_result_summary():
    r = _make_result(
        [
            Finding("A", "A", Severity.HIGH, ""),
            Finding("B", "B", Severity.MEDIUM, ""),
            Finding("C", "C", Severity.LOW, ""),
            Finding("D", "D", Severity.INFO, ""),
        ]
    )
    s = r.to_dict()["summary"]
    assert s == {
        "high": 1,
        "medium": 1,
        "low": 1,
        "info": 1,
        "total": 4,
        "suppressed": 0,
    }


def test_finding_roundtrip():
    f = Finding(
        "IOS-ATS-003a",
        "title",
        Severity.HIGH,
        "desc",
        "evidence",
        "rec",
        "MASVS-NETWORK-1",
        {"k": "v"},
    )
    assert Finding.from_dict(f.to_dict()) == f


def test_finding_masvs_field():
    f = Finding("R", "T", Severity.HIGH, "D", masvs="MASVS-RESILIENCE-3")
    d = f.to_dict()
    assert d["masvs"] == "MASVS-RESILIENCE-3"
    f2 = Finding.from_dict(d)
    assert f2.masvs == "MASVS-RESILIENCE-3"


# ── Metadata checker ──────────────────────────────────────────────────────────


def test_metadata_background_mode_voip():
    plist = {"UIBackgroundModes": ["voip"]}
    findings = check_metadata(plist)
    assert any(f.rule_id == "IOS-META-012a" for f in findings)
    voip_finding = next(f for f in findings if f.rule_id == "IOS-META-012a")
    assert voip_finding.severity == Severity.LOW


def test_metadata_sensitive_permissions():
    plist = {
        "NSCameraUsageDescription": "Take photos",
        "NSMicrophoneUsageDescription": "Record audio",
    }
    findings = check_metadata(plist)
    meta_b = [f for f in findings if f.rule_id == "IOS-META-012b"]
    assert len(meta_b) == 1
    assert "Camera" in meta_b[0].evidence or "camera" in meta_b[0].evidence.lower()


def test_metadata_missing_ats():
    findings = check_metadata({})
    assert any(f.rule_id == "IOS-META-012c" for f in findings)


def test_metadata_ats_present_no_012c():
    plist = {"NSAppTransportSecurity": {}}
    findings = check_metadata(plist)
    assert not any(f.rule_id == "IOS-META-012c" for f in findings)


def test_metadata_unknown_background_mode():
    plist = {"UIBackgroundModes": ["unknown-mode"]}
    findings = check_metadata(plist)
    assert not any(f.rule_id == "IOS-META-012a" for f in findings)


# ── Suppression ───────────────────────────────────────────────────────────────


def test_suppression_matches_rule_id():
    sup = Suppression(rule_id="IOS-ATS-003a")
    f = _finding("IOS-ATS-003a", "some evidence")
    assert sup.matches(f)


def test_suppression_no_match_different_rule():
    sup = Suppression(rule_id="IOS-ATS-003a")
    f = _finding("IOS-SEC-002", "evidence")
    assert not sup.matches(f)


def test_suppression_evidence_prefix():
    sup = Suppression(rule_id="IOS-SEC-002", evidence_prefix="AKIA")
    f = _finding("IOS-SEC-002", "AKIAIOSFODNN7EXAMPLE")
    assert sup.matches(f)


def test_suppression_evidence_prefix_no_match():
    sup = Suppression(rule_id="IOS-SEC-002", evidence_prefix="AKIA")
    f = _finding("IOS-SEC-002", "something else")
    assert not sup.matches(f)


def test_suppression_store_apply():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    # Start with empty store
    tmp_path.write_text("[]", encoding="utf-8")
    store = SuppressionStore(path=tmp_path)
    store.add("IOS-ATS-003a")
    findings = [
        _finding("IOS-ATS-003a"),
        _finding("IOS-SEC-002", "AKIAIOSFODNN7EXAMPLE"),
    ]
    active, suppressed = store.apply(findings)
    assert len(active) == 1
    assert active[0].rule_id == "IOS-SEC-002"
    assert len(suppressed) == 1
    assert suppressed[0].rule_id == "IOS-ATS-003a"
    tmp_path.unlink(missing_ok=True)


def test_suppression_store_roundtrip():
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        tmp_path = Path(tmp.name)
    tmp_path.write_text("[]", encoding="utf-8")
    store = SuppressionStore(path=tmp_path)
    store.add("IOS-DBG-004a", evidence_prefix="DEBUG", reason="test fixture")
    # Reload
    store2 = SuppressionStore(path=tmp_path)
    sups = store2.list_all()
    assert len(sups) == 1
    assert sups[0].rule_id == "IOS-DBG-004a"
    assert sups[0].evidence_prefix == "DEBUG"
    assert sups[0].reason == "test fixture"
    tmp_path.unlink(missing_ok=True)


# ── Report generation ─────────────────────────────────────────────────────────


def _make_full_result() -> ScanResult:
    r = ScanResult(
        app_id="com.example.app",
        app_version="2.0",
        build="100",
        ipa_name="Example.ipa",
        scan_id="abc12345-0000-0000-0000-000000000000",
        scanned_at="2026-05-10T00:00:00",
    )
    r.findings = [
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
    ]
    return r


def test_to_json_contains_findings():
    result = _make_full_result()
    output = to_json(result)
    data = json.loads(output)
    assert data["app_id"] == "com.example.app"
    assert len(data["findings"]) == 2
    assert data["findings"][0]["masvs"] == "MASVS-NETWORK-1"


def test_to_sarif_structure():
    result = _make_full_result()
    output = to_sarif(result)
    data = json.loads(output)
    assert data["version"] == "2.1.0"
    runs = data["runs"]
    assert len(runs) == 1
    assert runs[0]["tool"]["driver"]["name"] == "shingan"
    assert len(runs[0]["results"]) == 2


def test_to_html_english():
    result = _make_full_result()
    html = to_html(result, lang="en")
    assert "Findings" in html
    assert "Recommendation" in html
    assert "MASVS: MASVS-NETWORK-1" in html
    assert 'lang="en"' in html


def test_to_html_japanese():
    result = _make_full_result()
    html = to_html(result, lang="ja")
    assert "検出結果" in html
    assert "推奨事項" in html
    assert 'lang="ja"' in html


def test_to_html_diff_badges():
    result = _make_full_result()
    fp = result.findings[0].fingerprint()
    html = to_html(result, diff_new={fp}, lang="en")
    assert "NEW" in html
