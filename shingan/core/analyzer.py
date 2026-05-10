"""Main analysis orchestrator."""

from __future__ import annotations

import datetime
import uuid
from pathlib import Path

from shingan.core.ingest import ingest
from shingan.core.models import ScanResult
from shingan.core.rules import apply_custom_rules
from shingan.core.suppression import SuppressionStore
from shingan.core.checkers import (
    ats,
    binary_protection,
    crypto,
    debug_flags,
    keychain,
    metadata,
    protection,
    sbom,
    secrets,
    symbols,
)


def analyze(
    input_path: Path,
    work_dir: Path | None = None,
    suppression_store: SuppressionStore | None = None,
    custom_rules_dir: Path | None = None,
) -> ScanResult:
    """Run all checkers on an IPA / .app / .xcarchive and return a ScanResult."""
    bundle = ingest(input_path, work_dir)

    info = bundle.info_plist
    result = ScanResult(
        scan_id=str(uuid.uuid4()),
        scanned_at=datetime.datetime.utcnow().isoformat() + "Z",
        app_id=info.get("CFBundleIdentifier", "unknown"),
        app_version=info.get("CFBundleShortVersionString", "unknown"),
        build=info.get("CFBundleVersion", "unknown"),
        ipa_name=bundle.ipa_path.name,
    )

    result.findings += symbols.check(bundle.binary_path)
    result.findings += secrets.check(bundle.binary_path)
    result.findings += ats.check(bundle.info_plist)
    result.findings += debug_flags.check(bundle.binary_path, bundle.info_plist)
    result.findings += protection.check(bundle.binary_path)
    result.findings += binary_protection.check(bundle.binary_path)
    result.findings += crypto.check(bundle.binary_path)
    result.findings += keychain.check(bundle.binary_path)
    result.findings += sbom.check(bundle.binary_path, bundle.app_dir)
    result.findings += metadata.check(bundle.info_plist)
    result.findings += apply_custom_rules(
        bundle.binary_path,
        bundle.info_plist,
        **({"rules_dir": custom_rules_dir} if custom_rules_dir else {}),
    )

    if suppression_store:
        active, suppressed = suppression_store.apply(result.findings)
        result.findings = active
        result.suppressed_count = len(suppressed)

    if work_dir is None:
        bundle.cleanup()

    return result
