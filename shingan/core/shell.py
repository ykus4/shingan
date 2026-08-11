"""Thin wrapper around ``subprocess.run`` shared by every external-tool caller.

There were eight separate ``subprocess.run`` call sites, each re-implementing
the same timeout/capture/swallow-errors dance with slightly different logging.
``run_command`` centralises the policy:

* always capture text output, never inherit the parent's stdio
* always pass an explicit timeout
* never raise for a non-zero exit — callers get a ``CommandResult`` and decide
* distinguish "tool is not installed" from "tool ran and failed"
"""

from __future__ import annotations

import logging
import subprocess
from dataclasses import dataclass
from pathlib import Path

from shingan.core.constants import SUBPROCESS_TIMEOUT

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class CommandResult:
    """Outcome of an external command invocation."""

    returncode: int
    stdout: str
    stderr: str
    #: True when the executable itself could not be found on PATH.
    missing: bool = False
    #: True when the command exceeded its timeout.
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        """True when the command ran to completion with exit status 0."""
        return self.returncode == 0 and not self.missing and not self.timed_out

    def lines(self) -> list[str]:
        """stdout split into lines (empty list when the command did not succeed)."""
        return self.stdout.splitlines() if self.ok else []


def run_command(
    argv: list[str],
    *,
    timeout: int = SUBPROCESS_TIMEOUT,
    cwd: Path | None = None,
) -> CommandResult:
    """Run ``argv`` and return its outcome. Never raises."""
    try:
        completed = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
            cwd=str(cwd) if cwd else None,
        )
    except FileNotFoundError:
        logger.debug("Command not found: %s", argv[0])
        return CommandResult(returncode=127, stdout="", stderr="", missing=True)
    except subprocess.TimeoutExpired:
        logger.debug("Command timed out after %ss: %s", timeout, argv[0])
        return CommandResult(returncode=124, stdout="", stderr="", timed_out=True)
    except OSError as exc:
        logger.debug("Command failed to start (%s): %s", argv[0], exc)
        return CommandResult(returncode=1, stdout="", stderr=str(exc))

    return CommandResult(
        returncode=completed.returncode,
        stdout=completed.stdout or "",
        stderr=completed.stderr or "",
    )


def extract_strings(binary_path: Path, min_length: int) -> set[str]:
    """Return printable strings of at least ``min_length`` from a binary.

    Returns an empty set when the ``strings`` utility is unavailable or fails,
    so callers can treat "no strings" and "no tool" identically.
    """
    result = run_command(
        ["strings", "-a", "-n", str(min_length), str(binary_path)],
    )
    if not result.ok:
        logger.debug("strings failed for %s (rc=%s)", binary_path, result.returncode)
        return set()
    return set(result.lines())
