"""Tests for baseline diffing."""

from __future__ import annotations

from shingan.core.diff import compare


def test_new_finding_is_detected(make_result, make_finding) -> None:
    baseline = make_result([make_finding("IOS-ATS-003a")])
    current = make_result(
        [
            make_finding("IOS-ATS-003a"),
            make_finding("IOS-SEC-002-aws_key", evidence="AKIAIOSFODNN7EXAMPLE"),
        ]
    )

    diff = compare(baseline, current)

    assert [f.rule_id for f in diff.new] == ["IOS-SEC-002-aws_key"]
    assert diff.fixed == []
    assert len(diff.persisted) == 1


def test_fixed_finding_is_detected(make_result, make_finding) -> None:
    baseline = make_result([make_finding("IOS-ATS-003a"), make_finding("IOS-DBG-004a")])
    current = make_result([make_finding("IOS-ATS-003a")])

    diff = compare(baseline, current)

    assert [f.rule_id for f in diff.fixed] == ["IOS-DBG-004a"]
    assert diff.new == []


def test_empty_scans(make_result) -> None:
    diff = compare(make_result([]), make_result([]))
    assert (diff.new, diff.fixed, diff.persisted) == ([], [], [])


def test_all_new_against_empty_baseline(make_result, make_finding) -> None:
    diff = compare(make_result([]), make_result([make_finding("A"), make_finding("B")]))
    assert len(diff.new) == 2
    assert diff.persisted == []


def test_all_fixed_against_empty_current(make_result, make_finding) -> None:
    diff = compare(make_result([make_finding("A")]), make_result([]))
    assert len(diff.fixed) == 1


def test_same_rule_different_evidence_is_new(make_result, make_finding) -> None:
    """Fingerprints include evidence, so a different hit is a distinct finding."""
    baseline = make_result([make_finding("R", evidence="first")])
    current = make_result([make_finding("R", evidence="second")])

    diff = compare(baseline, current)

    assert len(diff.new) == 1
    assert len(diff.fixed) == 1
    assert diff.persisted == []


def test_summary_counts(make_result, make_finding) -> None:
    diff = compare(
        make_result([make_finding("A"), make_finding("B")]),
        make_result([make_finding("B"), make_finding("C")]),
    )
    assert diff.summary() == {"new": 1, "fixed": 1, "persisted": 1}


def test_fingerprint_sets(make_result, make_finding) -> None:
    baseline = make_result([make_finding("OLD")])
    current = make_result([make_finding("NEW")])

    diff = compare(baseline, current)

    assert diff.new_fingerprints == {current.findings[0].fingerprint()}
    assert diff.fixed_fingerprints == {baseline.findings[0].fingerprint()}
