"""Shared pytest fixtures.

Previously each test built its own temporary files inline and nothing stopped a
test from reading or writing the developer's real ``~/.shingan`` directory.
"""

from __future__ import annotations

import plistlib
import zipfile
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

from shingan.core.context import AndroidCheckContext, CheckContext
from shingan.core.models import Finding, ScanResult, Severity
from shingan.core.storage import ScanStore
from shingan.core.suppression import SuppressionStore


@pytest.fixture(autouse=True)
def isolated_shingan_home(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Iterator[Path]:
    """Point SHINGAN_HOME at a temp directory for every test.

    Autouse so no test can accidentally read or mutate the real ~/.shingan.
    """
    home = tmp_path / "shingan_home"
    home.mkdir()
    monkeypatch.setenv("SHINGAN_HOME", str(home))
    yield home


@pytest.fixture
def make_finding() -> Callable[..., Finding]:
    def _make(
        rule_id: str = "IOS-TEST-001",
        *,
        severity: Severity = Severity.HIGH,
        evidence: str = "",
        title: str | None = None,
        masvs: str = "",
        extra: dict | None = None,
    ) -> Finding:
        return Finding(
            rule_id=rule_id,
            title=title or rule_id,
            severity=severity,
            description="",
            evidence=evidence,
            masvs=masvs,
            extra=extra or {},
        )

    return _make


@pytest.fixture
def make_result() -> Callable[..., ScanResult]:
    def _make(
        findings: list[Finding] | None = None,
        *,
        app_id: str = "com.example",
        app_version: str = "1.0",
        build: str = "1",
        artifact_name: str = "test.ipa",
        platform: str = "ios",
        scan_id: str = "abc12345-0000-0000-0000-000000000000",
        scanned_at: str = "2026-05-10T00:00:00Z",
    ) -> ScanResult:
        return ScanResult(
            app_id=app_id,
            app_version=app_version,
            build=build,
            artifact_name=artifact_name,
            platform=platform,
            scan_id=scan_id,
            scanned_at=scanned_at,
            findings=list(findings or []),
        )

    return _make


@pytest.fixture
def make_ios_ctx() -> Callable[..., CheckContext]:
    """Build a CheckContext with pre-seeded caches (no subprocess or LIEF)."""

    def _make(
        strings: set[str] | None = None,
        info_plist: dict | None = None,
        *,
        symbol_names: set[str] | None = None,
        objc_classes: list[str] | None = None,
    ) -> CheckContext:
        ctx = CheckContext(
            binary_path=Path("/nonexistent-binary"), info_plist=info_plist or {}
        )
        resolved = set() if strings is None else strings
        symbols = symbol_names or set()
        ctx.__dict__.update(
            strings=resolved,
            symbol_names=symbols,
            lief_binary=None,
            objc_classes=objc_classes or [],
            all_text=resolved | symbols,
        )
        return ctx

    return _make


@pytest.fixture
def make_android_ctx() -> Callable[..., AndroidCheckContext]:
    """Build an AndroidCheckContext with pre-seeded caches (no androguard)."""

    def _make(
        dex_strings: set[str] | None = None,
        native_strings: set[str] | None = None,
        *,
        manifest_summary: dict[str, str] | None = None,
    ) -> AndroidCheckContext:
        ctx = AndroidCheckContext(apk_path=Path("/nonexistent.apk"))
        dex = dex_strings or set()
        native = native_strings or set()
        ctx.__dict__.update(
            apk=None,
            dex_analysis=None,
            native_binaries=[],
            strings=native,
            dex_strings=dex,
            symbol_names=set(),
            all_text=dex | native,
            manifest_summary=manifest_summary or {},
        )
        return ctx

    return _make


@pytest.fixture
def store(tmp_path: Path) -> ScanStore:
    return ScanStore(db_path=tmp_path / "scans.db")


@pytest.fixture
def suppression_store(tmp_path: Path) -> SuppressionStore:
    return SuppressionStore(path=tmp_path / "suppressions.json")


# ── Synthetic artifacts ───────────────────────────────────────────────────────

MINIMAL_PLIST = {
    "CFBundleIdentifier": "com.example.app",
    "CFBundleShortVersionString": "1.2.3",
    "CFBundleVersion": "42",
    "CFBundleExecutable": "Example",
}


@pytest.fixture
def app_bundle(tmp_path: Path) -> Path:
    """A minimal .app directory that ingest() accepts."""
    app_dir = tmp_path / "Example.app"
    app_dir.mkdir()
    (app_dir / "Info.plist").write_bytes(plistlib.dumps(MINIMAL_PLIST))
    (app_dir / "Example").write_bytes(b"\xcf\xfa\xed\xfe placeholder binary")
    return app_dir


@pytest.fixture
def ipa_file(tmp_path: Path) -> Path:
    """A minimal, well-formed .ipa containing Payload/Example.app."""
    ipa = tmp_path / "Example.ipa"
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/Example.app/Info.plist", plistlib.dumps(MINIMAL_PLIST))
        zf.writestr("Payload/Example.app/Example", "placeholder binary")
    return ipa
