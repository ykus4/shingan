"""Tests for Finding / ScanResult / Severity."""

from __future__ import annotations

from shingan.core.models import (
    SEVERITY_ORDER,
    Finding,
    ScanResult,
    Severity,
    severity_counts,
)

# ── Severity ordering ─────────────────────────────────────────────────────────


def test_severity_ranks_are_strictly_ordered() -> None:
    ranks = [s.rank for s in SEVERITY_ORDER]
    assert ranks == sorted(ranks)
    assert len(set(ranks)) == len(ranks)


def test_critical_is_most_severe() -> None:
    assert Severity.CRITICAL.rank < Severity.HIGH.rank < Severity.INFO.rank


def test_at_least_includes_self() -> None:
    assert Severity.HIGH.at_least(Severity.HIGH)


def test_at_least_is_severity_threshold() -> None:
    assert Severity.CRITICAL.at_least(Severity.HIGH)
    assert not Severity.MEDIUM.at_least(Severity.HIGH)
    assert Severity.HIGH.at_least(Severity.LOW)


def test_every_severity_has_a_colour() -> None:
    for severity in Severity:
        assert severity.color


# ── severity_counts ───────────────────────────────────────────────────────────


def test_severity_counts_includes_all_levels(make_finding) -> None:
    counts = severity_counts([make_finding(severity=Severity.CRITICAL)])
    assert counts["critical"] == 1
    # Every level is present even at zero, so report consumers can index safely.
    assert set(counts) == {s.value for s in Severity}


def test_severity_counts_empty() -> None:
    assert all(v == 0 for v in severity_counts([]).values())


# ── Finding ───────────────────────────────────────────────────────────────────


def test_finding_roundtrip() -> None:
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


def test_finding_critical_roundtrip() -> None:
    f = Finding("R", "T", Severity.CRITICAL, "D")
    assert Finding.from_dict(f.to_dict()).severity is Severity.CRITICAL


def test_fingerprint_is_stable_across_equal_findings(make_finding) -> None:
    a = make_finding("R", evidence="same")
    b = make_finding("R", evidence="same")
    assert a.fingerprint() == b.fingerprint()


def test_fingerprint_ignores_evidence_tail(make_finding) -> None:
    """Long evidence is truncated, so cosmetic tail changes keep the fingerprint."""
    base = "x" * 200
    a = make_finding("R", evidence=base + "aaa")
    b = make_finding("R", evidence=base + "bbb")
    assert a.fingerprint() == b.fingerprint()


def test_is_dynamic_flag(make_finding) -> None:
    assert make_finding(extra={"source": "dynamic"}).is_dynamic
    assert not make_finding().is_dynamic


# ── ScanResult ────────────────────────────────────────────────────────────────


def test_summary_counts_by_severity(make_result, make_finding) -> None:
    result = make_result(
        [
            make_finding("A", severity=Severity.CRITICAL),
            make_finding("B", severity=Severity.HIGH),
            make_finding("C", severity=Severity.MEDIUM),
            make_finding("D", severity=Severity.LOW),
            make_finding("E", severity=Severity.INFO),
        ]
    )
    s = result.to_dict()["summary"]
    assert (s["critical"], s["high"], s["medium"], s["low"], s["info"]) == (1,) * 5
    assert s["total"] == 5
    assert s["static"]["total"] == 5
    assert s["dynamic"]["total"] == 0


def test_summary_splits_static_and_dynamic(make_result, make_finding) -> None:
    result = make_result(
        [
            make_finding("S", severity=Severity.HIGH),
            make_finding(
                "D",
                severity=Severity.HIGH,
                extra={"source": "dynamic", "outcome": "bypassed"},
            ),
        ]
    )
    s = result.to_dict()["summary"]
    assert s["high"] == 2  # top-level total spans both sources
    assert s["static"]["total"] == 1
    assert s["dynamic"]["total"] == 1
    assert s["dynamic"]["bypassed"] == 1
    assert s["dynamic"]["resistant"] == 0


def test_ipa_name_kept_for_backward_compatibility(make_result) -> None:
    result = make_result(artifact_name="Example.apk", platform="android")
    d = result.to_dict()
    # Existing consumers read "ipa_name"; "artifact_name" is the new spelling.
    assert d["ipa_name"] == "Example.apk"
    assert d["artifact_name"] == "Example.apk"
    assert result.ipa_name == "Example.apk"


def test_from_dict_accepts_legacy_ipa_name() -> None:
    payload = {
        "app_id": "com.example",
        "app_version": "1.0",
        "build": "1",
        "ipa_name": "Legacy.ipa",
        "findings": [],
    }
    assert ScanResult.from_dict(payload).artifact_name == "Legacy.ipa"


def test_from_dict_prefers_artifact_name() -> None:
    payload = {
        "app_id": "com.example",
        "app_version": "1.0",
        "build": "1",
        "ipa_name": "old.ipa",
        "artifact_name": "new.apk",
        "findings": [],
    }
    assert ScanResult.from_dict(payload).artifact_name == "new.apk"


def test_scan_result_roundtrip(make_result, make_finding) -> None:
    original = make_result([make_finding("R", severity=Severity.CRITICAL)])
    restored = ScanResult.from_dict(original.to_dict())
    assert restored.app_id == original.app_id
    assert restored.artifact_name == original.artifact_name
    assert restored.platform == original.platform
    assert restored.findings == original.findings
