"""Tests for the Click CLI."""

from __future__ import annotations

import importlib
import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from shingan.cli import cli


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def test_importing_the_cli_creates_no_database(
    isolated_shingan_home: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Importing the module used to create ~/.shingan/shingan.db as a side effect."""
    import shingan.cli

    importlib.reload(shingan.cli)

    assert not (isolated_shingan_home / "shingan.db").exists()


def test_version_option(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "shingan" in result.output


# ── scan ──────────────────────────────────────────────────────────────────────


def test_scan_text_output(runner: CliRunner, ipa_file: Path) -> None:
    result = runner.invoke(cli, ["scan", str(ipa_file), "--no-save"])
    assert result.exit_code == 0


def test_scan_text_to_file_is_not_empty(
    runner: CliRunner, ipa_file: Path, tmp_path: Path
) -> None:
    """--format text --out used to write a zero-byte file."""
    out = tmp_path / "report.txt"
    result = runner.invoke(
        cli, ["scan", str(ipa_file), "--no-save", "--format", "text", "--out", str(out)]
    )

    assert result.exit_code == 0
    content = out.read_text()
    assert content.strip()
    assert "shingan report" in content
    assert "Example.ipa" in content


def test_scan_json_to_file(runner: CliRunner, ipa_file: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.json"
    result = runner.invoke(
        cli, ["scan", str(ipa_file), "--no-save", "--format", "json", "--out", str(out)]
    )

    assert result.exit_code == 0
    data = json.loads(out.read_text())
    assert data["app_id"] == "com.example.app"
    assert data["ipa_name"] == "Example.ipa"


def test_scan_sarif_to_file(runner: CliRunner, ipa_file: Path, tmp_path: Path) -> None:
    out = tmp_path / "report.sarif"
    runner.invoke(
        cli,
        ["scan", str(ipa_file), "--no-save", "--format", "sarif", "--out", str(out)],
    )
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"


def test_scan_accepts_app_directory(runner: CliRunner, app_bundle: Path) -> None:
    """dir_okay=False used to reject .app directories that ingest() supports."""
    result = runner.invoke(cli, ["scan", str(app_bundle), "--no-save"])
    assert result.exit_code == 0


def test_scan_missing_file_exits_2(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(cli, ["scan", str(tmp_path / "absent.ipa"), "--no-save"])
    # Click's own existence check rejects the path before the command body runs.
    assert result.exit_code == 2


def test_scan_unsupported_input_exits_2(runner: CliRunner, tmp_path: Path) -> None:
    junk = tmp_path / "thing.txt"
    junk.write_text("nope")
    result = runner.invoke(cli, ["scan", str(junk), "--no-save"])
    assert result.exit_code == 2


def test_scan_saves_and_reports_the_db_path(runner: CliRunner, ipa_file: Path) -> None:
    """The 'Saved → …' line used to print None."""
    result = runner.invoke(cli, ["scan", str(ipa_file)])
    assert result.exit_code == 0
    assert "Saved scan" in result.output
    assert "None" not in result.output
    assert "shingan.db" in result.output


# ── --fail-on gate ────────────────────────────────────────────────────────────


# The placeholder IPA yields medium/low/info findings but no high or critical, so
# the gate is exercised on both sides of the threshold.


def test_fail_on_medium_exits_1(runner: CliRunner, ipa_file: Path) -> None:
    result = runner.invoke(
        cli, ["scan", str(ipa_file), "--no-save", "--fail-on", "medium"]
    )
    assert result.exit_code == 1
    assert "FAIL" in result.output


def test_fail_on_high_passes_when_nothing_is_that_severe(
    runner: CliRunner, ipa_file: Path
) -> None:
    result = runner.invoke(
        cli, ["scan", str(ipa_file), "--no-save", "--fail-on", "high"]
    )
    assert result.exit_code == 0
    assert "PASS" in result.output


def test_fail_on_none_exits_0(runner: CliRunner, ipa_file: Path) -> None:
    result = runner.invoke(
        cli, ["scan", str(ipa_file), "--no-save", "--fail-on", "none"]
    )
    assert result.exit_code == 0
    # The gate is skipped entirely, so neither verdict is printed.
    assert "PASS" not in result.output
    assert "FAIL" not in result.output


def test_fail_on_accepts_critical(runner: CliRunner, ipa_file: Path) -> None:
    result = runner.invoke(
        cli, ["scan", str(ipa_file), "--no-save", "--fail-on", "critical"]
    )
    assert result.exit_code == 0
    assert "PASS" in result.output


def test_fail_on_accepts_info(runner: CliRunner, ipa_file: Path) -> None:
    """info is the lowest severity, so every finding trips the gate."""
    result = runner.invoke(
        cli, ["scan", str(ipa_file), "--no-save", "--fail-on", "info"]
    )
    assert result.exit_code == 1


# ── list / export / diff ──────────────────────────────────────────────────────


def test_list_empty(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["list"])
    assert result.exit_code == 0
    assert "No scans found" in result.output


def test_list_after_scan(runner: CliRunner, ipa_file: Path) -> None:
    runner.invoke(cli, ["scan", str(ipa_file)])
    result = runner.invoke(cli, ["list"])
    assert result.exit_code == 0
    assert "com.example.app" in result.output


def test_export_unknown_scan(runner: CliRunner, tmp_path: Path) -> None:
    result = runner.invoke(
        cli, ["export", "does-not-exist", "--out", str(tmp_path / "o.json")]
    )
    assert result.exit_code == 1
    assert "not found" in result.output.lower()


def test_export_roundtrip(runner: CliRunner, ipa_file: Path, tmp_path: Path) -> None:
    scan = runner.invoke(cli, ["scan", str(ipa_file), "--format", "json"])
    scan_id = json.loads(scan.stdout)["scan_id"]

    out = tmp_path / "export.json"
    result = runner.invoke(cli, ["export", scan_id, "--out", str(out)])

    assert result.exit_code == 0
    assert json.loads(out.read_text())["scan_id"] == scan_id


def test_export_text_format(runner: CliRunner, ipa_file: Path, tmp_path: Path) -> None:
    scan = runner.invoke(cli, ["scan", str(ipa_file), "--format", "json"])
    scan_id = json.loads(scan.stdout)["scan_id"]

    out = tmp_path / "export.txt"
    runner.invoke(cli, ["export", scan_id, "--format", "text", "--out", str(out)])

    assert "shingan report" in out.read_text()


def test_diff_unknown_scans(runner: CliRunner) -> None:
    result = runner.invoke(cli, ["diff", "nope-a", "nope-b"])
    assert result.exit_code == 1


def test_diff_identical_scans(runner: CliRunner, ipa_file: Path) -> None:
    a = json.loads(
        runner.invoke(cli, ["scan", str(ipa_file), "--format", "json"]).stdout
    )
    b = json.loads(
        runner.invoke(cli, ["scan", str(ipa_file), "--format", "json"]).stdout
    )

    result = runner.invoke(cli, ["diff", a["scan_id"], b["scan_id"]])

    assert result.exit_code == 0
    assert "persisted" in result.output


def test_scan_with_missing_baseline_warns(runner: CliRunner, ipa_file: Path) -> None:
    result = runner.invoke(
        cli, ["scan", str(ipa_file), "--no-save", "--baseline", "nonexistent"]
    )
    assert result.exit_code == 0
    assert "not found" in result.output


# ── suppress (offline error handling) ─────────────────────────────────────────


def test_suppress_list_without_server(runner: CliRunner) -> None:
    """Points the user at `shingan serve` rather than dumping a traceback."""
    result = runner.invoke(cli, ["suppress", "list", "--url", "http://127.0.0.1:9"])
    assert result.exit_code == 1
    assert "shingan serve" in result.output
