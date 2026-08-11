"""Tests for path resolution.

The three stores each captured ``SHINGAN_HOME`` into a module-level constant at
import time, so overriding it later had no effect. These tests pin the lazy
behaviour that replaced it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from shingan.core.paths import (
    default_db_path,
    default_rules_dir,
    default_suppressions_path,
    legacy_scans_dir,
    shingan_home,
)


def test_env_override_is_honoured(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHINGAN_HOME", str(tmp_path / "custom"))
    assert shingan_home() == tmp_path / "custom"


def test_env_change_takes_effect_after_import(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Resolution is lazy, so a later change is picked up."""
    monkeypatch.setenv("SHINGAN_HOME", str(tmp_path / "first"))
    assert shingan_home() == tmp_path / "first"

    monkeypatch.setenv("SHINGAN_HOME", str(tmp_path / "second"))
    assert shingan_home() == tmp_path / "second"


def test_falls_back_to_home_directory(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SHINGAN_HOME", raising=False)
    assert shingan_home() == Path.home() / ".shingan"


def test_empty_env_var_falls_back(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHINGAN_HOME", "")
    assert shingan_home() == Path.home() / ".shingan"


def test_tilde_is_expanded(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SHINGAN_HOME", "~/shingan-data")
    assert shingan_home() == Path.home() / "shingan-data"


def test_derived_paths_share_one_root(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setenv("SHINGAN_HOME", str(tmp_path))
    assert default_db_path() == tmp_path / "shingan.db"
    assert default_suppressions_path() == tmp_path / "suppressions.json"
    assert default_rules_dir() == tmp_path / "rules"
    assert legacy_scans_dir() == tmp_path / "scans"
