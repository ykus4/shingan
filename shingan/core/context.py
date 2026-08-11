"""Binary analysis context — shared, cached access to string table and binary.

Every checker receives a context object instead of a raw ``Path``.  The context
lazily extracts strings and parses the binary exactly once, so repeated calls
across checkers do not re-invoke subprocesses or re-parse the binary.

Usage::

    ctx = CheckContext(binary_path, info_plist)
    strings: set[str] = ctx.strings          # extracted once, cached
    binary  = ctx.lief_binary                # parsed once, cached (or None)
    symbols: set[str] = ctx.symbol_names     # derived from lief_binary
"""

from __future__ import annotations

import logging
from functools import cached_property
from pathlib import Path
from typing import Any

from shingan.core.constants import SECRETS_STRINGS_MIN_LEN, STRINGS_MIN_LEN
from shingan.core.shell import extract_strings

logger = logging.getLogger(__name__)


class CheckContext:
    """Shared state passed to every iOS checker.

    Attributes:
        binary_path: Path to the main Mach-O executable.
        info_plist: Parsed Info.plist dictionary (may be empty).
        app_dir: Optional path to the .app bundle directory.
    """

    platform = "ios"

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
        return extract_strings(self.binary_path, STRINGS_MIN_LEN)

    @cached_property
    def long_strings(self) -> set[str]:
        """Strings at least ``SECRETS_STRINGS_MIN_LEN`` characters long.

        Derived by filtering :attr:`strings` rather than re-running ``strings``
        with a higher ``-n``: the previous implementation scanned the whole
        binary a second time to obtain a strict subset of what it already had.
        """
        return {s for s in self.strings if len(s) >= SECRETS_STRINGS_MIN_LEN}

    @cached_property
    def lief_binary(self) -> Any | None:
        """Parsed LIEF Mach-O binary object, or None if parsing fails."""
        try:
            import lief

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
        except Exception as exc:
            logger.debug("objc_classes extraction failed: %s", exc)
            return []

    @cached_property
    def all_text(self) -> set[str]:
        """Union of ``strings`` output and symbol names — the broadest text corpus."""
        return self.strings | self.symbol_names


class AndroidCheckContext:
    """Shared state passed to every Android checker.

    Attributes:
        apk_path: Path to the original .apk file.
        work_dir: Directory where the APK was extracted.
    """

    platform = "android"

    def __init__(
        self,
        apk_path: Path,
        work_dir: Path | None = None,
        apk: Any | None = None,
    ) -> None:
        self.apk_path = apk_path
        self.work_dir = work_dir or apk_path.parent
        # Ingestion already parses the APK to read manifest metadata; accepting
        # it here avoids a second full parse of the same file.
        if apk is not None:
            self.__dict__["apk"] = apk

    # ── Lazy properties ───────────────────────────────────────────────────────

    @cached_property
    def apk(self) -> Any | None:
        """androguard APK object, or None if parsing fails."""
        try:
            from androguard.core.apk import APK

            return APK(str(self.apk_path))
        except Exception as exc:
            logger.debug("androguard APK parse failed for %s: %s", self.apk_path, exc)
            return None

    @cached_property
    def dex_analysis(self) -> Any | None:
        """androguard Analysis object for DEX bytecode, or None if parsing fails."""
        try:
            from androguard.misc import AnalyzeAPK

            _, _, dx = AnalyzeAPK(str(self.apk_path))
            return dx
        except Exception as exc:
            logger.debug("androguard AnalyzeAPK failed for %s: %s", self.apk_path, exc)
            return None

    @cached_property
    def native_binaries(self) -> list[Path]:
        """Paths to .so files extracted from the APK."""
        lib_dir = self.work_dir / "lib"
        if not lib_dir.exists():
            return []
        return list(lib_dir.rglob("*.so"))

    @cached_property
    def strings(self) -> set[str]:
        """Printable strings from all bundled .so binaries (via `strings` command).

        Returns an empty set if the command fails or no native libraries are found.
        """
        result: set[str] = set()
        for so_path in self.native_binaries:
            result |= extract_strings(so_path, STRINGS_MIN_LEN)
        return result

    @cached_property
    def dex_strings(self) -> set[str]:
        """String constants extracted from DEX bytecode via androguard."""
        dx = self.dex_analysis
        if dx is None:
            return set()
        result: set[str] = set()
        try:
            for string_analysis in dx.get_strings():
                result.add(string_analysis.get_orig_value())
        except Exception as exc:
            logger.debug("dex_strings extraction failed: %s", exc)
        return result

    @cached_property
    def symbol_names(self) -> set[str]:
        """Method and field names from DEX analysis."""
        dx = self.dex_analysis
        if dx is None:
            return set()
        result: set[str] = set()
        try:
            for method in dx.get_methods():
                result.add(method.name)
        except Exception as exc:
            logger.debug("symbol_names extraction failed: %s", exc)
        return result

    @cached_property
    def all_text(self) -> set[str]:
        """Union of native .so strings, DEX strings, and method names."""
        return self.strings | self.dex_strings | self.symbol_names

    @cached_property
    def long_strings(self) -> set[str]:
        """Secret-scanning corpus: DEX + native strings above the length floor."""
        return {
            s
            for s in (self.dex_strings | self.strings)
            if len(s) >= SECRETS_STRINGS_MIN_LEN
        }

    @cached_property
    def manifest_summary(self) -> dict[str, str]:
        """Flat manifest key/value map used by custom rules.

        Cached because custom-rule evaluation previously rebuilt this for every
        rule that targeted ``android_manifest``.
        """
        apk = self.apk
        if apk is None:
            return {}
        summary: dict[str, str] = {}
        try:
            summary["package"] = apk.get_package() or ""
            summary["versionName"] = apk.get_androidversion_name() or ""
            summary["versionCode"] = str(apk.get_androidversion_code() or "")
            summary["minSdkVersion"] = str(apk.get_min_sdk_version() or "")
            summary["targetSdkVersion"] = str(apk.get_target_sdk_version() or "")
            summary["debuggable"] = str(
                apk.get_attribute_value("application", "debuggable") or "false"
            )
            summary["allowBackup"] = str(
                apk.get_attribute_value("application", "allowBackup") or "false"
            )
            summary["permissions"] = " ".join(apk.get_permissions())
        except Exception as exc:
            logger.debug("manifest_summary extraction failed: %s", exc)
        return summary
