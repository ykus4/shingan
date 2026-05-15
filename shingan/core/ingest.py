"""Ingestion: supports .ipa, .app (directory), .xcarchive, and .apk inputs."""

from __future__ import annotations

import logging
import plistlib
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class IPABundle:
    ipa_path: Path  # original input path
    work_dir: Path  # temp extraction directory (may equal ipa_path for .app)
    app_dir: Path  # path to the .app bundle
    binary_path: Path  # main executable
    info_plist: dict = field(default_factory=dict)
    entitlements_path: Path | None = None
    _owned: bool = False  # True if we created work_dir and should clean it up

    def cleanup(self) -> None:
        if self._owned and self.work_dir.exists():
            shutil.rmtree(self.work_dir)

    def __enter__(self) -> "IPABundle":
        return self

    def __exit__(self, *_) -> None:
        self.cleanup()


@dataclass
class APKBundle:
    apk_path: Path  # original .apk file
    work_dir: Path  # temp extraction directory
    package_name: str  # Android package name (e.g. com.example.app)
    version_name: str  # human-readable version (e.g. "1.2.3")
    version_code: str  # internal build number
    _owned: bool = False  # True if we created work_dir and should clean it up

    def cleanup(self) -> None:
        if self._owned and self.work_dir.exists():
            shutil.rmtree(self.work_dir)

    def __enter__(self) -> "APKBundle":
        return self

    def __exit__(self, *_) -> None:
        self.cleanup()


def ingest(input_path: Path, work_dir: Path | None = None) -> IPABundle | APKBundle:
    """Accept .ipa, .app directory, .xcarchive, or .apk and return a bundle."""
    input_path = Path(input_path).resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    suffix = input_path.suffix.lower()

    if suffix == ".apk":
        return ingest_apk(input_path, work_dir)
    elif suffix == ".ipa":
        return _ingest_ipa(input_path, work_dir)
    elif suffix == ".app" and input_path.is_dir():
        return _ingest_app(input_path)
    elif suffix == ".xcarchive" and input_path.is_dir():
        return _ingest_xcarchive(input_path, work_dir)
    elif input_path.is_dir() and any(input_path.glob("*.app")):
        # bare directory containing a .app
        app_dirs = list(input_path.glob("*.app"))
        return _ingest_app(app_dirs[0])
    else:
        raise ValueError(
            f"Unsupported input: {input_path}. "
            "Accepted: .ipa file, .app directory, .xcarchive directory, .apk file."
        )


def _resolve_app(
    app_dir: Path, source_path: Path, work_dir: Path, owned: bool
) -> IPABundle:
    info_plist_path = app_dir / "Info.plist"
    if not info_plist_path.exists():
        raise ValueError(f"Info.plist not found in {app_dir}")

    with open(info_plist_path, "rb") as f:
        info_plist = plistlib.load(f)

    bundle_executable = info_plist.get("CFBundleExecutable")
    if not bundle_executable:
        raise ValueError("Info.plist missing CFBundleExecutable")

    binary_path = app_dir / bundle_executable
    if not binary_path.exists():
        raise ValueError(f"Binary not found: {binary_path}")

    return IPABundle(
        ipa_path=source_path,
        work_dir=work_dir,
        app_dir=app_dir,
        binary_path=binary_path,
        info_plist=info_plist,
        _owned=owned,
    )


def _ingest_ipa(ipa_path: Path, work_dir: Path | None) -> IPABundle:
    owned = work_dir is None
    if owned:
        work_dir = Path(tempfile.mkdtemp(prefix="shingan_"))
    else:
        work_dir = Path(work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)

    with zipfile.ZipFile(ipa_path, "r") as zf:
        zf.extractall(work_dir)

    payload = work_dir / "Payload"
    if not payload.exists():
        raise ValueError("Invalid IPA: no Payload directory found")

    app_dirs = list(payload.glob("*.app"))
    if not app_dirs:
        raise ValueError("Invalid IPA: no .app bundle found in Payload/")

    return _resolve_app(app_dirs[0], ipa_path, work_dir, owned)


def _ingest_app(app_dir: Path) -> IPABundle:
    """Use a .app directory directly (no extraction needed)."""
    return _resolve_app(app_dir, app_dir, app_dir.parent, owned=False)


def _ingest_xcarchive(xcarchive_path: Path, work_dir: Path | None) -> IPABundle:
    """Extract the .app from an .xcarchive Products/Applications/ directory."""
    apps_dir = xcarchive_path / "Products" / "Applications"
    if not apps_dir.exists():
        raise ValueError(f"xcarchive has no Products/Applications: {xcarchive_path}")

    app_dirs = list(apps_dir.glob("*.app"))
    if not app_dirs:
        raise ValueError(f"No .app found in xcarchive Applications: {xcarchive_path}")

    return _resolve_app(app_dirs[0], xcarchive_path, xcarchive_path, owned=False)


def ingest_apk(apk_path: Path, work_dir: Path | None = None) -> APKBundle:
    """Extract and parse an Android APK file."""
    try:
        from androguard.core.apk import APK  # type: ignore[import]
    except ImportError as exc:
        raise ImportError(
            "androguard is required for APK analysis. Install it with: uv add androguard"
        ) from exc

    apk_path = Path(apk_path).resolve()
    owned = work_dir is None
    if owned:
        work_dir = Path(tempfile.mkdtemp(prefix="shingan_apk_"))
    else:
        work_dir = Path(work_dir)
        work_dir.mkdir(parents=True, exist_ok=True)

    # Extract APK contents for later analysis (native libs, resources, etc.)
    try:
        with zipfile.ZipFile(apk_path, "r") as zf:
            zf.extractall(work_dir)
    except zipfile.BadZipFile as exc:
        if owned:
            shutil.rmtree(work_dir, ignore_errors=True)
        raise ValueError(f"Invalid APK (not a zip archive): {apk_path}") from exc

    # Parse manifest metadata via androguard
    try:
        apk = APK(str(apk_path))
        package_name = apk.get_package() or "unknown"
        version_name = apk.get_androidversion_name() or "unknown"
        version_code = str(apk.get_androidversion_code() or "unknown")
    except Exception as exc:
        logger.debug("androguard APK parse failed for %s: %s", apk_path, exc)
        package_name = version_name = version_code = "unknown"

    return APKBundle(
        apk_path=apk_path,
        work_dir=work_dir,
        package_name=package_name,
        version_name=version_name,
        version_code=version_code,
        _owned=owned,
    )
