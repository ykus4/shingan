"""Unit tests for individual checkers using synthetic inputs."""

from __future__ import annotations


from shingan.core.checkers import ats
from shingan.core.checkers.secrets import _shannon_entropy
from shingan.core.diff import compare
from shingan.core.models import Finding, ScanResult, Severity


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
    assert s == {"high": 1, "medium": 1, "low": 1, "info": 1, "total": 4}


def test_finding_roundtrip():
    f = Finding(
        "IOS-ATS-003a", "title", Severity.HIGH, "desc", "evidence", "rec", {"k": "v"}
    )
    assert Finding.from_dict(f.to_dict()) == f
