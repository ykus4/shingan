"""Ingestion: supports .ipa, .app (directory), .xcarchive, and .apk inputs."""

from __future__ import annotations

import logging
import plistlib
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from shingan.core.archive import remove_tree, safe_extract_zip

logger = logging.getLogger(__name__)


class _CleanupMixin:
    """Shared cleanup/context-manager behaviour for extracted bundles.

    Implemented as a plain mixin rather than a dataclass base so subclasses keep
    a natural field order and ``work_dir`` stays an ordinary field.
    """

    work_dir: Path
    #: True when shingan created ``work_dir`` and is responsible for removing it.
    owned: bool

    def cleanup(self) -> None:
        """Remove the extraction directory if this bundle owns it."""
        if self.owned and self.work_dir.exists():
            remove_tree(self.work_dir)

    def __enter__(self):
        return self

    def __exit__(self, *_: object) -> None:
        self.cleanup()


@dataclass
class IPABundle(_CleanupMixin):
    ipa_path: Path  # original input path
    work_dir: Path  # temp extraction directory (may be the .app's parent)
    app_dir: Path  # path to the .app bundle
    binary_path: Path  # main executable
    info_plist: dict = field(default_factory=dict)
    owned: bool = False

    @property
    def artifact_path(self) -> Path:
        return self.ipa_path


@dataclass
class APKBundle(_CleanupMixin):
    apk_path: Path  # original .apk file
    work_dir: Path  # temp extraction directory
    package_name: str = "unknown"  # Android package name (e.g. com.example.app)
    version_name: str = "unknown"  # human-readable version (e.g. "1.2.3")
    version_code: str = "unknown"  # internal build number
    #: androguard APK object parsed during ingestion, reused by the check
    #: context so the APK is only parsed once per scan.
    apk: Any | None = None
    owned: bool = False

    @property
    def artifact_path(self) -> Path:
        return self.apk_path


def ingest(input_path: Path, work_dir: Path | None = None) -> IPABundle | APKBundle:
    """Accept .ipa, .app directory, .xcarchive, or .apk and return a bundle.

    This is the single dispatch point for input formats; callers branch on the
    returned bundle type rather than re-inspecting the file extension.
    """
    input_path = Path(input_path).resolve()
    if not input_path.exists():
        raise FileNotFoundError(f"Input not found: {input_path}")

    suffix = input_path.suffix.lower()

    if suffix == ".apk":
        return ingest_apk(input_path, work_dir)
    if suffix == ".ipa":
        return _ingest_ipa(input_path, work_dir)
    if suffix == ".app" and input_path.is_dir():
        return _ingest_app(input_path)
    if suffix == ".xcarchive" and input_path.is_dir():
        return _ingest_xcarchive(input_path)
    if input_path.is_dir():
        app_dirs = sorted(input_path.glob("*.app"))
        if app_dirs:
            return _ingest_app(app_dirs[0])

    raise ValueError(
        f"Unsupported input: {input_path}. "
        "Accepted: .ipa file, .app directory, .xcarchive directory, .apk file."
    )


def _prepare_work_dir(work_dir: Path | None, prefix: str) -> tuple[Path, bool]:
    """Return (work_dir, owned). Creates a temp dir when none was supplied."""
    if work_dir is None:
        return Path(tempfile.mkdtemp(prefix=prefix)), True
    resolved = Path(work_dir)
    resolved.mkdir(parents=True, exist_ok=True)
    return resolved, False


def _resolve_app(
    app_dir: Path, source_path: Path, work_dir: Path, owned: bool
) -> IPABundle:
    info_plist_path = app_dir / "Info.plist"
    if not info_plist_path.exists():
        raise ValueError(f"Info.plist not found in {app_dir}")

    with info_plist_path.open("rb") as f:
        info_plist = plistlib.load(f)

    bundle_executable = info_plist.get("CFBundleExecutable")
    if not bundle_executable:
        raise ValueError("Info.plist missing CFBundleExecutable")

    # CFBundleExecutable comes from the artifact under analysis, so it is
    # untrusted: refuse a value that points outside the .app directory.
    binary_path = (app_dir / bundle_executable).resolve()
    try:
        binary_path.relative_to(app_dir.resolve())
    except ValueError as exc:
        raise ValueError(
            f"CFBundleExecutable escapes the app bundle: {bundle_executable!r}"
        ) from exc

    if not binary_path.exists():
        raise ValueError(f"Binary not found: {binary_path}")

    return IPABundle(
        ipa_path=source_path,
        work_dir=work_dir,
        app_dir=app_dir,
        binary_path=binary_path,
        info_plist=info_plist,
        owned=owned,
    )


def _ingest_ipa(ipa_path: Path, work_dir: Path | None) -> IPABundle:
    resolved_dir, owned = _prepare_work_dir(work_dir, "shingan_")

    try:
        safe_extract_zip(ipa_path, resolved_dir)
    except Exception:
        if owned:
            remove_tree(resolved_dir)
        raise

    payload = resolved_dir / "Payload"
    if not payload.exists():
        if owned:
            remove_tree(resolved_dir)
        raise ValueError("Invalid IPA: no Payload directory found")

    app_dirs = sorted(payload.glob("*.app"))
    if not app_dirs:
        if owned:
            remove_tree(resolved_dir)
        raise ValueError("Invalid IPA: no .app bundle found in Payload/")

    return _resolve_app(app_dirs[0], ipa_path, resolved_dir, owned)


def _ingest_app(app_dir: Path) -> IPABundle:
    """Use a .app directory directly (no extraction needed)."""
    return _resolve_app(app_dir, app_dir, app_dir.parent, owned=False)


def _ingest_xcarchive(xcarchive_path: Path) -> IPABundle:
    """Use the .app inside an .xcarchive Products/Applications/ directory.

    No extraction happens, so there is nothing for a caller-supplied work_dir to
    hold; the parameter used to be accepted and silently ignored.
    """
    apps_dir = xcarchive_path / "Products" / "Applications"
    if not apps_dir.exists():
        raise ValueError(f"xcarchive has no Products/Applications: {xcarchive_path}")

    app_dirs = sorted(apps_dir.glob("*.app"))
    if not app_dirs:
        raise ValueError(f"No .app found in xcarchive Applications: {xcarchive_path}")

    return _resolve_app(app_dirs[0], xcarchive_path, xcarchive_path, owned=False)


def ingest_apk(apk_path: Path, work_dir: Path | None = None) -> APKBundle:
    """Extract and parse an Android APK file."""
    try:
        from androguard.core.apk import APK
    except ImportError as exc:
        raise ImportError(
            "androguard is required for APK analysis. Install it with: uv add androguard"
        ) from exc

    apk_path = Path(apk_path).resolve()
    resolved_dir, owned = _prepare_work_dir(work_dir, "shingan_apk_")

    # Extract APK contents for later analysis (native libs, resources, etc.)
    try:
        safe_extract_zip(apk_path, resolved_dir)
    except ValueError as exc:
        if owned:
            remove_tree(resolved_dir)
        raise ValueError(f"Invalid APK: {apk_path} ({exc})") from exc

    # Parse manifest metadata via androguard.  The parsed object is carried on
    # the bundle so AndroidCheckContext does not parse the APK a second time.
    apk: Any | None = None
    package_name = version_name = version_code = "unknown"
    try:
        apk = APK(str(apk_path))
        package_name = apk.get_package() or "unknown"
        version_name = apk.get_androidversion_name() or "unknown"
        version_code = str(apk.get_androidversion_code() or "unknown")
    except Exception as exc:
        logger.warning("androguard APK parse failed for %s: %s", apk_path, exc)

    return APKBundle(
        apk_path=apk_path,
        work_dir=resolved_dir,
        package_name=package_name,
        version_name=version_name,
        version_code=version_code,
        apk=apk,
        owned=owned,
    )
