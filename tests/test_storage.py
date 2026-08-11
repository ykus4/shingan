"""Tests for the SQLite scan store."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from shingan.core.constants import SCHEMA_VERSION
from shingan.core.models import Severity
from shingan.core.storage import ScanStore


def test_save_returns_the_database_path(store: ScanStore, make_result) -> None:
    """save() used to return None while the CLI printed it as 'Saved → …'."""
    returned = store.save(make_result())
    assert returned == store.db_path
    assert returned.exists()


def test_save_then_load_roundtrip(store: ScanStore, make_result, make_finding) -> None:
    result = make_result([make_finding("R", severity=Severity.CRITICAL)], scan_id="s1")
    store.save(result)

    loaded = store.load("s1")
    assert loaded.app_id == result.app_id
    assert loaded.artifact_name == result.artifact_name
    assert [f.rule_id for f in loaded.findings] == ["R"]
    assert loaded.findings[0].severity is Severity.CRITICAL


def test_load_missing_raises(store: ScanStore) -> None:
    with pytest.raises(FileNotFoundError, match="Scan not found"):
        store.load("nope")


def test_save_is_idempotent_on_scan_id(store: ScanStore, make_result) -> None:
    store.save(make_result(scan_id="dup", app_version="1.0"))
    store.save(make_result(scan_id="dup", app_version="2.0"))
    assert len(store.list_scans()) == 1
    assert store.load("dup").app_version == "2.0"


def test_schema_version_is_recorded(store: ScanStore) -> None:
    assert store.schema_version() == SCHEMA_VERSION


# ── Listing ───────────────────────────────────────────────────────────────────


def test_list_scans_newest_first(store: ScanStore, make_result) -> None:
    store.save(make_result(scan_id="old", scanned_at="2026-01-01T00:00:00Z"))
    store.save(make_result(scan_id="new", scanned_at="2026-06-01T00:00:00Z"))

    assert [s["scan_id"] for s in store.list_scans()] == ["new", "old"]


def test_list_scans_includes_summary(
    store: ScanStore, make_result, make_finding
) -> None:
    store.save(make_result([make_finding(severity=Severity.HIGH)], scan_id="s"))
    summary = store.list_scans()[0]["summary"]
    assert summary["high"] == 1
    assert summary["total"] == 1


def test_list_scans_filters_by_app_id(store: ScanStore, make_result) -> None:
    store.save(make_result(scan_id="a", app_id="com.a"))
    store.save(make_result(scan_id="b", app_id="com.b"))

    assert [s["scan_id"] for s in store.list_scans(app_id="com.a")] == ["a"]


def test_list_scans_respects_limit(store: ScanStore, make_result) -> None:
    for i in range(5):
        store.save(
            make_result(scan_id=f"s{i}", scanned_at=f"2026-01-0{i + 1}T00:00:00Z")
        )
    assert len(store.list_scans(limit=2)) == 2


def test_list_scans_exposes_both_name_keys(store: ScanStore, make_result) -> None:
    store.save(make_result(scan_id="s", artifact_name="App.apk"))
    row = store.list_scans()[0]
    assert row["ipa_name"] == "App.apk"
    assert row["artifact_name"] == "App.apk"


# ── latest_for_app ────────────────────────────────────────────────────────────


def test_latest_for_app_returns_newest(store: ScanStore, make_result) -> None:
    store.save(
        make_result(scan_id="old", app_id="com.x", scanned_at="2026-01-01T00:00:00Z")
    )
    store.save(
        make_result(scan_id="new", app_id="com.x", scanned_at="2026-06-01T00:00:00Z")
    )

    latest = store.latest_for_app("com.x")
    assert latest is not None
    assert latest.scan_id == "new"


def test_latest_for_app_unknown_returns_none(store: ScanStore) -> None:
    assert store.latest_for_app("com.missing") is None


# ── delete / exists ───────────────────────────────────────────────────────────


def test_delete_reports_whether_a_row_was_removed(
    store: ScanStore, make_result
) -> None:
    store.save(make_result(scan_id="s"))
    assert store.delete("s") is True
    # Previously delete() always "succeeded", so the API returned 204 for
    # unknown IDs instead of 404.
    assert store.delete("s") is False


def test_delete_removes_dangling_baseline(store: ScanStore, make_result) -> None:
    store.save(make_result(scan_id="s", app_id="com.x"))
    store.set_baseline("com.x", "s")

    store.delete("s")

    assert store.get_baseline("com.x") is None


def test_exists(store: ScanStore, make_result) -> None:
    store.save(make_result(scan_id="s"))
    assert store.exists("s")
    assert not store.exists("other")


# ── Baselines ─────────────────────────────────────────────────────────────────


def test_baseline_set_and_get(store: ScanStore) -> None:
    store.set_baseline("com.x", "scan1")
    assert store.get_baseline("com.x") == "scan1"


def test_baseline_overwrite(store: ScanStore) -> None:
    store.set_baseline("com.x", "scan1")
    store.set_baseline("com.x", "scan2")
    assert store.get_baseline("com.x") == "scan2"


def test_baseline_unknown_app(store: ScanStore) -> None:
    assert store.get_baseline("com.missing") is None


# ── Legacy JSON migration ─────────────────────────────────────────────────────


def _legacy_scan(scan_id: str) -> dict:
    return {
        "scan_id": scan_id,
        "app_id": "com.legacy",
        "app_version": "1.0",
        "build": "1",
        "ipa_name": "Legacy.ipa",
        "scanned_at": "2026-01-01T00:00:00Z",
        "findings": [],
    }


def test_migrates_legacy_json_scans(
    isolated_shingan_home: Path, tmp_path: Path
) -> None:
    legacy = isolated_shingan_home / "scans"
    legacy.mkdir()
    (legacy / "a.json").write_text(json.dumps(_legacy_scan("legacy-1")))

    store = ScanStore(db_path=tmp_path / "db.sqlite")

    assert store.load("legacy-1").app_id == "com.legacy"


def test_migration_runs_only_once(isolated_shingan_home: Path, tmp_path: Path) -> None:
    """The legacy directory is renamed, so it is not re-scanned every startup."""
    legacy = isolated_shingan_home / "scans"
    legacy.mkdir()
    (legacy / "a.json").write_text(json.dumps(_legacy_scan("legacy-1")))

    ScanStore(db_path=tmp_path / "db.sqlite")

    assert not legacy.exists()
    assert (isolated_shingan_home / "scans.migrated").exists()


def test_migration_skips_corrupt_files(
    isolated_shingan_home: Path, tmp_path: Path
) -> None:
    legacy = isolated_shingan_home / "scans"
    legacy.mkdir()
    (legacy / "bad.json").write_text("{not json")
    (legacy / "good.json").write_text(json.dumps(_legacy_scan("legacy-ok")))

    store = ScanStore(db_path=tmp_path / "db.sqlite")

    assert store.exists("legacy-ok")


def test_no_legacy_directory_is_fine(tmp_path: Path) -> None:
    assert ScanStore(db_path=tmp_path / "db.sqlite").list_scans() == []
