"""IPA ingestion: unzip, locate .app bundle and main binary."""

from __future__ import annotations

import plistlib
import shutil
import tempfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class IPABundle:
    ipa_path: Path
    work_dir: Path
    app_dir: Path
    binary_path: Path
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


def ingest(ipa_path: Path, work_dir: Path | None = None) -> IPABundle:
    """Extract IPA and return an IPABundle with resolved paths."""
    ipa_path = Path(ipa_path).resolve()
    if not ipa_path.exists():
        raise FileNotFoundError(f"IPA not found: {ipa_path}")

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
    app_dir = app_dirs[0]

    info_plist_path = app_dir / "Info.plist"
    if not info_plist_path.exists():
        raise ValueError("Invalid IPA: Info.plist not found")

    with open(info_plist_path, "rb") as f:
        info_plist = plistlib.load(f)

    bundle_executable = info_plist.get("CFBundleExecutable")
    if not bundle_executable:
        raise ValueError("Info.plist missing CFBundleExecutable")

    binary_path = app_dir / bundle_executable
    if not binary_path.exists():
        raise ValueError(f"Binary not found: {binary_path}")

    # entitlements are embedded in the binary (codesign) — resolved later by checkers
    bundle = IPABundle(
        ipa_path=ipa_path,
        work_dir=work_dir,
        app_dir=app_dir,
        binary_path=binary_path,
        info_plist=info_plist,
        _owned=owned,
    )
    return bundle
