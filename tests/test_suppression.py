"""Tests for suppression storage and matching."""

from __future__ import annotations

import json
import logging
from pathlib import Path

import pytest

from shingan.core.suppression import Suppression, SuppressionStore

# ── Matching ──────────────────────────────────────────────────────────────────


def test_matches_on_rule_id(make_finding) -> None:
    assert Suppression(rule_id="IOS-ATS-003a").matches(
        make_finding("IOS-ATS-003a", evidence="some evidence")
    )


def test_does_not_match_other_rule(make_finding) -> None:
    assert not Suppression(rule_id="IOS-ATS-003a").matches(make_finding("IOS-SEC-002"))


def test_matches_evidence_prefix(make_finding) -> None:
    sup = Suppression(rule_id="IOS-SEC-002", evidence_prefix="AKIA")
    assert sup.matches(make_finding("IOS-SEC-002", evidence="AKIAIOSFODNN7EXAMPLE"))


def test_evidence_prefix_must_match(make_finding) -> None:
    sup = Suppression(rule_id="IOS-SEC-002", evidence_prefix="AKIA")
    assert not sup.matches(make_finding("IOS-SEC-002", evidence="something else"))


def test_empty_prefix_matches_all_evidence(make_finding) -> None:
    sup = Suppression(rule_id="R")
    assert sup.matches(make_finding("R", evidence="anything at all"))


def test_roundtrip_dict() -> None:
    sup = Suppression("R", "prefix", "reason")
    assert Suppression.from_dict(sup.to_dict()) == sup


# ── Store ─────────────────────────────────────────────────────────────────────


def test_apply_partitions_findings(
    suppression_store: SuppressionStore, make_finding
) -> None:
    suppression_store.add("IOS-ATS-003a")

    active, suppressed = suppression_store.apply(
        [make_finding("IOS-ATS-003a"), make_finding("IOS-SEC-002")]
    )

    assert [f.rule_id for f in active] == ["IOS-SEC-002"]
    assert [f.rule_id for f in suppressed] == ["IOS-ATS-003a"]


def test_apply_with_no_suppressions(
    suppression_store: SuppressionStore, make_finding
) -> None:
    active, suppressed = suppression_store.apply([make_finding("R")])
    assert len(active) == 1
    assert suppressed == []


def test_persists_across_instances(tmp_path: Path) -> None:
    path = tmp_path / "sup.json"
    SuppressionStore(path=path).add("IOS-DBG-004a", "DEBUG", "test fixture")

    reloaded = SuppressionStore(path=path).list_all()

    assert len(reloaded) == 1
    assert reloaded[0].rule_id == "IOS-DBG-004a"
    assert reloaded[0].evidence_prefix == "DEBUG"
    assert reloaded[0].reason == "test fixture"


def test_add_is_idempotent(suppression_store: SuppressionStore) -> None:
    """Repeated adds used to append duplicate entries indefinitely."""
    for _ in range(3):
        suppression_store.add("R", "prefix")
    assert len(suppression_store.list_all()) == 1


def test_add_distinguishes_by_prefix(suppression_store: SuppressionStore) -> None:
    suppression_store.add("R", "a")
    suppression_store.add("R", "b")
    assert len(suppression_store.list_all()) == 2


def test_remove_returns_count(suppression_store: SuppressionStore) -> None:
    suppression_store.add("R")
    assert suppression_store.remove("R") == 1
    assert suppression_store.remove("R") == 0


def test_remove_matches_prefix(suppression_store: SuppressionStore) -> None:
    suppression_store.add("R", "keep")
    suppression_store.add("R", "drop")

    assert suppression_store.remove("R", "drop") == 1

    remaining = suppression_store.list_all()
    assert [s.evidence_prefix for s in remaining] == ["keep"]


def test_list_all_returns_a_copy(suppression_store: SuppressionStore) -> None:
    suppression_store.add("R")
    suppression_store.list_all().clear()
    assert len(suppression_store.list_all()) == 1


def test_missing_file_is_an_empty_store(tmp_path: Path) -> None:
    assert SuppressionStore(path=tmp_path / "absent.json").list_all() == []


# ── Corrupt input handling ────────────────────────────────────────────────────


def test_corrupt_file_is_reported_not_silently_ignored(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A corrupt file used to look identical to 'no suppressions configured'."""
    path = tmp_path / "sup.json"
    path.write_text("{ not valid json", encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        store = SuppressionStore(path=path)

    assert store.list_all() == []
    assert any("Could not read suppressions" in m for m in caplog.messages)


def test_non_list_payload_is_reported(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "sup.json"
    path.write_text(json.dumps({"rule_id": "R"}), encoding="utf-8")

    with caplog.at_level(logging.WARNING):
        store = SuppressionStore(path=path)

    assert store.list_all() == []
    assert any("must contain a list" in m for m in caplog.messages)


def test_malformed_entry_is_skipped_but_others_load(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "sup.json"
    path.write_text(
        json.dumps([{"no_rule_id": True}, {"rule_id": "GOOD"}]), encoding="utf-8"
    )

    with caplog.at_level(logging.WARNING):
        store = SuppressionStore(path=path)

    assert [s.rule_id for s in store.list_all()] == ["GOOD"]


def test_save_does_not_leave_a_temp_file(suppression_store: SuppressionStore) -> None:
    suppression_store.add("R")
    siblings = list(suppression_store.path.parent.iterdir())
    assert all(not p.name.endswith(".tmp") for p in siblings)
