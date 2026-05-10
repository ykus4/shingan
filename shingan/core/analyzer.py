"""Main analysis orchestrator."""

from __future__ import annotations

import datetime
import uuid
from pathlib import Path

from shingan.core.ingest import ingest
from shingan.core.models import ScanResult
from shingan.core.checkers import ats, debug_flags, protection, secrets, symbols


def analyze(ipa_path: Path, work_dir: Path | None = None) -> ScanResult:
    """Run all checkers on an IPA and return a ScanResult."""
    bundle = ingest(ipa_path, work_dir)

    info = bundle.info_plist
    result = ScanResult(
        scan_id=str(uuid.uuid4()),
        scanned_at=datetime.datetime.utcnow().isoformat() + "Z",
        app_id=info.get("CFBundleIdentifier", "unknown"),
        app_version=info.get("CFBundleShortVersionString", "unknown"),
        build=info.get("CFBundleVersion", "unknown"),
        ipa_name=ipa_path.name,
    )

    result.findings += symbols.check(bundle.binary_path)
    result.findings += secrets.check(bundle.binary_path)
    result.findings += ats.check(bundle.info_plist)
    result.findings += debug_flags.check(bundle.binary_path, bundle.info_plist)
    result.findings += protection.check(bundle.binary_path)

    if work_dir is None:
        bundle.cleanup()

    return result
