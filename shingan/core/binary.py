"""Binary analysis context — shared, cached access to string table and LIEF binary.

Every checker receives a `CheckContext` instead of a raw `Path`.  The context
lazily extracts strings and parses the Mach-O binary exactly once, so repeated
calls across checkers do not re-invoke subprocesses or re-parse the binary.

Usage::

    ctx = CheckContext(binary_path, info_plist)
    strings: set[str] = ctx.strings          # extracted once, cached
    binary  = ctx.lief_binary                # parsed once, cached (or None)
    symbols: set[str] = ctx.symbol_names     # derived from lief_binary
"""

from __future__ import annotations

import logging
import subprocess
from functools import cached_property
from pathlib import Path
from typing import Any

from shingan.core.constants import STRINGS_MIN_LEN, SUBPROCESS_TIMEOUT

logger = logging.getLogger(__name__)


class CheckContext:
    """Shared state passed to every checker.

    Attributes:
        binary_path: Path to the main Mach-O executable.
        info_plist: Parsed Info.plist dictionary (may be empty).
        app_dir: Optional path to the .app bundle directory.
    """

    def __init__(
        self,
        binary_path: Path,
        info_plist: dict,
        app_dir: Path | None = None,
    ) -> None:
        self.binary_path = binary_path
        self.info_plist = info_plist
        self.app_dir = app_dir

    # ── Lazy properties ───────────────────────────────────────────────────────

    @cached_property
    def strings(self) -> set[str]:
        """All printable strings extracted from the binary (via `strings`).

        Returns an empty set if the command fails or is unavailable.
        """
        try:
            result = subprocess.run(
                ["strings", "-a", "-n", str(STRINGS_MIN_LEN), str(self.binary_path)],
                capture_output=True,
                text=True,
                timeout=SUBPROCESS_TIMEOUT,
            )
            return set(result.stdout.splitlines())
        except Exception as exc:
            logger.debug("strings command failed for %s: %s", self.binary_path, exc)
            return set()

    @cached_property
    def lief_binary(self) -> Any | None:
        """Parsed LIEF Mach-O binary object, or None if parsing fails."""
        try:
            import lief  # type: ignore[import]

            binary = lief.parse(str(self.binary_path))
            if binary is None:
                logger.debug("lief.parse returned None for %s", self.binary_path)
            return binary
        except Exception as exc:
            logger.debug("lief.parse failed for %s: %s", self.binary_path, exc)
            return None

    @cached_property
    def symbol_names(self) -> set[str]:
        """Set of all symbol names from the Mach-O symbol table.

        Returns an empty set if LIEF parsing fails.
        """
        binary = self.lief_binary
        if binary is None:
            return set()
        try:
            return {sym.name for sym in binary.symbols}
        except Exception as exc:
            logger.debug("symbol_names extraction failed: %s", exc)
            return set()

    @cached_property
    def objc_classes(self) -> list[str]:
        """List of Objective-C class names found in the binary."""
        binary = self.lief_binary
        if binary is None:
            return []
        try:
            return [cls.name for cls in binary.objc_classes]
        except Exception:
            return []

    @cached_property
    def all_text(self) -> set[str]:
        """Union of ``strings`` output and symbol names — the broadest text corpus."""
        return self.strings | self.symbol_names
