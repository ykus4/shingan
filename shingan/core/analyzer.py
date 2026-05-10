"""Main analysis orchestrator."""

from __future__ import annotations

import datetime
import logging
import uuid
from pathlib import Path

from shingan.core.binary import CheckContext
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
from shingan.core.ingest import ingest
from shingan.core.models import ScanResult
from shingan.core.rules import DEFAULT_RULES_DIR, apply_custom_rules
from shingan.core.suppression import SuppressionStore

logger = logging.getLogger(__name__)


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

    # Build one shared context — strings and binary are parsed lazily and cached.
    ctx = CheckContext(
        binary_path=bundle.binary_path,
        info_plist=bundle.info_plist,
        app_dir=bundle.app_dir,
    )

    # Checkers that operate on the binary via CheckContext
    binary_checkers = [
        symbols.check,
        secrets.check,
        debug_flags.check,
        protection.check,
        binary_protection.check,
        crypto.check,
        keychain.check,
        sbom.check,
    ]
    for checker in binary_checkers:
        try:
            result.findings += checker(ctx)
        except Exception:
            logger.exception("Checker %s failed — skipping", checker.__module__)

    # Checkers that operate on Info.plist only
    plist_checkers = [
        lambda c: ats.check(c.info_plist),
        lambda c: metadata.check(c.info_plist),
    ]
    for checker in plist_checkers:
        try:
            result.findings += checker(ctx)
        except Exception:
            logger.exception("Plist checker failed — skipping")

    # Custom YAML rules
    try:
        rules_dir = custom_rules_dir or DEFAULT_RULES_DIR
        result.findings += apply_custom_rules(ctx, rules_dir=rules_dir)
    except Exception:
        logger.exception("Custom rules failed — skipping")

    if suppression_store:
        active, suppressed = suppression_store.apply(result.findings)
        result.findings = active
        result.suppressed_count = len(suppressed)

    if work_dir is None:
        bundle.cleanup()

    return result
