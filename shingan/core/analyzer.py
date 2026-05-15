"""Main analysis orchestrator."""

from __future__ import annotations

import datetime
import logging
import uuid
from pathlib import Path

from shingan.core.context import AndroidCheckContext, CheckContext
from shingan.core.checkers.ios import (
    ats,
    binary_protection,
    crypto,
    data_handling,
    debug_flags,
    keychain,
    metadata,
    protection,
    sbom,
    secrets,
    symbols,
    webview,
)
from shingan.core.checkers.android import (
    binary_protection as android_binary_protection,
    crypto as android_crypto,
    data_handling as android_data_handling,
    debug_flags as android_debug_flags,
    manifest as android_manifest,
    network_security as android_network_security,
    permissions as android_permissions,
    protection as android_protection,
    sbom as android_sbom,
    secrets as android_secrets,
    signing as android_signing,
    webview as android_webview,
)
from shingan.core.ingest import APKBundle, ingest
from shingan.core.models import ScanResult
from shingan.core.rules import DEFAULT_RULES_DIR, apply_custom_rules
from shingan.core.suppression import SuppressionStore

logger = logging.getLogger(__name__)


def analyze(
    input_path: Path,
    work_dir: Path | None = None,
    suppression_store: SuppressionStore | None = None,
    custom_rules_dir: Path | None = None,
    dynamic: bool = False,
    device_udid: str | None = None,
    dynamic_timeout: int = 30,
) -> ScanResult:
    """Run all checkers on an IPA / .app / .xcarchive / .apk and return a ScanResult."""
    if Path(input_path).suffix.lower() == ".apk":
        return _analyze_android(
            input_path, work_dir, suppression_store, custom_rules_dir
        )
    return _analyze_ios(
        input_path,
        work_dir,
        suppression_store,
        custom_rules_dir,
        dynamic=dynamic,
        device_udid=device_udid,
        dynamic_timeout=dynamic_timeout,
    )


def _analyze_ios(
    input_path: Path,
    work_dir: Path | None = None,
    suppression_store: SuppressionStore | None = None,
    custom_rules_dir: Path | None = None,
    dynamic: bool = False,
    device_udid: str | None = None,
    dynamic_timeout: int = 30,
) -> ScanResult:
    """Run all iOS checkers on an IPA / .app / .xcarchive."""
    bundle = ingest(input_path, work_dir)

    info = bundle.info_plist
    result = ScanResult(
        scan_id=str(uuid.uuid4()),
        scanned_at=datetime.datetime.utcnow().isoformat() + "Z",
        app_id=info.get("CFBundleIdentifier", "unknown"),
        app_version=info.get("CFBundleShortVersionString", "unknown"),
        build=info.get("CFBundleVersion", "unknown"),
        ipa_name=bundle.ipa_path.name,
        platform="ios",
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
        webview.check,
        data_handling.check,
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

    # Dynamic analysis (optional, iOS only)
    if dynamic:
        try:
            from shingan.core.dynamic import run_dynamic_checks

            result.findings += run_dynamic_checks(
                bundle_id=result.app_id,
                device_udid=device_udid,
                timeout=dynamic_timeout,
            )
        except Exception:
            logger.exception("Dynamic analysis failed — skipping")

    if suppression_store:
        active, suppressed = suppression_store.apply(result.findings)
        result.findings = active
        result.suppressed_count = len(suppressed)

    if work_dir is None:
        bundle.cleanup()

    return result


def _analyze_android(
    input_path: Path,
    work_dir: Path | None = None,
    suppression_store: SuppressionStore | None = None,
    custom_rules_dir: Path | None = None,
) -> ScanResult:
    """Run all Android checkers on an APK."""
    from shingan.core.ingest import ingest_apk

    bundle = ingest_apk(input_path, work_dir)
    assert isinstance(bundle, APKBundle)

    result = ScanResult(
        scan_id=str(uuid.uuid4()),
        scanned_at=datetime.datetime.utcnow().isoformat() + "Z",
        app_id=bundle.package_name,
        app_version=bundle.version_name,
        build=bundle.version_code,
        ipa_name=bundle.apk_path.name,
        platform="android",
    )

    ctx = AndroidCheckContext(apk_path=bundle.apk_path, work_dir=bundle.work_dir)

    checkers = [
        android_manifest.check,
        android_debug_flags.check,
        android_network_security.check,
        android_binary_protection.check,
        android_crypto.check,
        android_secrets.check,
        android_protection.check,
        android_permissions.check,
        android_sbom.check,
        android_signing.check,
        android_webview.check,
        android_data_handling.check,
    ]
    for checker in checkers:
        try:
            result.findings += checker(ctx)
        except Exception:
            logger.exception("Android checker %s failed — skipping", checker.__module__)

    if suppression_store:
        active, suppressed = suppression_store.apply(result.findings)
        result.findings = active
        result.suppressed_count = len(suppressed)

    if work_dir is None:
        bundle.cleanup()

    return result
