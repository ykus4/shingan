"""Tests for the shared subprocess wrapper."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import patch

from shingan.core.shell import CommandResult, extract_strings, run_command


def test_successful_command() -> None:
    result = run_command(["echo", "hello"])
    assert result.ok
    assert result.stdout.strip() == "hello"
    assert result.returncode == 0
    assert not result.missing
    assert not result.timed_out


def test_nonzero_exit_is_not_an_error() -> None:
    """A failing command returns a result rather than raising."""
    result = run_command(["false"])
    assert not result.ok
    assert result.returncode != 0
    assert not result.missing


def test_missing_executable_is_flagged() -> None:
    result = run_command(["shingan-definitely-not-a-real-binary"])
    assert result.missing
    assert not result.ok
    assert result.returncode == 127


def test_timeout_is_flagged() -> None:
    with patch(
        "subprocess.run",
        side_effect=subprocess.TimeoutExpired(cmd=["sleep"], timeout=1),
    ):
        result = run_command(["sleep", "10"], timeout=1)

    assert result.timed_out
    assert not result.ok
    assert result.returncode == 124


def test_oserror_is_captured() -> None:
    with patch("subprocess.run", side_effect=OSError("exec format error")):
        result = run_command(["whatever"])

    assert not result.ok
    assert "exec format error" in result.stderr


def test_lines_only_returned_on_success() -> None:
    assert run_command(["printf", "a\\nb\\n"]).lines() == ["a", "b"]
    assert run_command(["false"]).lines() == []


def test_cwd_is_honoured(tmp_path: Path) -> None:
    (tmp_path / "marker.txt").write_text("x")
    result = run_command(["ls"], cwd=tmp_path)
    assert "marker.txt" in result.stdout


def test_command_result_is_immutable() -> None:
    result = CommandResult(returncode=0, stdout="", stderr="")
    try:
        result.returncode = 1  # type: ignore[misc]
    except Exception as exc:
        assert "frozen" in str(exc).lower() or isinstance(exc, AttributeError)
    else:
        raise AssertionError("CommandResult should be frozen")


# ── extract_strings ───────────────────────────────────────────────────────────


def test_extract_strings_on_missing_file() -> None:
    """Degrades to an empty set rather than raising."""
    assert extract_strings(Path("/nonexistent-binary-xyz"), 5) == set()


def test_extract_strings_parses_output() -> None:
    fake = CommandResult(returncode=0, stdout="alpha\nbeta\nalpha\n", stderr="")
    with patch("shingan.core.shell.run_command", return_value=fake):
        assert extract_strings(Path("/x"), 5) == {"alpha", "beta"}


def test_extract_strings_when_tool_absent() -> None:
    missing = CommandResult(returncode=127, stdout="", stderr="", missing=True)
    with patch("shingan.core.shell.run_command", return_value=missing):
        assert extract_strings(Path("/x"), 5) == set()
