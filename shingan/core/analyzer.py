"""Main analysis orchestrator."""

from __future__ import annotations

import datetime
import logging
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, cast

from shingan.core.checkers.registry import checkers_for, run_checkers
from shingan.core.context import AndroidCheckContext, CheckContext
from shingan.core.ingest import APKBundle, IPABundle, ingest
from shingan.core.models import Finding, ScanResult
from shingan.core.rules import apply_custom_rules
from shingan.core.suppression import SuppressionStore

logger = logging.getLogger(__name__)

#: Platforms shingan can analyse.
Platform = Literal["ios", "android"]


@dataclass(frozen=True)
class DynamicOptions:
    """Settings for optional on-device (frida) analysis."""

    enabled: bool = False
    device_udid: str | None = None
    timeout: int = 30


def _utc_now_iso() -> str:
    """Current UTC time as an ISO-8601 string with a trailing ``Z``.

    ``datetime.utcnow()`` is deprecated from Python 3.12 because it returns a
    naive datetime that silently misrepresents the timezone.
    """
    return (
        datetime.datetime.now(datetime.UTC)
        .replace(tzinfo=None, microsecond=0)
        .isoformat()
        + "Z"
    )


def analyze(
    input_path: Path,
    work_dir: Path | None = None,
    suppression_store: SuppressionStore | None = None,
    custom_rules_dir: Path | None = None,
    dynamic: bool = False,
    device_udid: str | None = None,
    dynamic_timeout: int = 30,
) -> ScanResult:
    """Run all checkers on an IPA / .app / .xcarchive / .apk and return a ScanResult.

    Input-format dispatch happens once, inside :func:`ingest`; this function
    branches on the resulting bundle type rather than re-inspecting the suffix.
    """
    options = DynamicOptions(
        enabled=dynamic, device_udid=device_udid, timeout=dynamic_timeout
    )
    bundle = ingest(input_path, work_dir)
    try:
        result: ScanResult
        ctx: CheckContext | AndroidCheckContext
        if isinstance(bundle, APKBundle):
            result, ctx = _prepare_android(bundle)
        else:
            result, ctx = _prepare_ios(bundle)

        result.findings.extend(run_checkers(checkers_for(result.platform), ctx))

        # Custom YAML rules apply to both platforms.
        try:
            result.findings.extend(apply_custom_rules(ctx, rules_dir=custom_rules_dir))
        except Exception:
            logger.exception("Custom rules failed — skipping")

        if options.enabled:
            result.findings.extend(
                _run_dynamic(result.app_id, cast("Platform", result.platform), options)
            )

        if suppression_store:
            active, suppressed = suppression_store.apply(result.findings)
            result.findings = active
            result.suppressed_count = len(suppressed)

        return result
    finally:
        # Only removes the directory when ingestion created it.
        bundle.cleanup()


def _new_result(
    *,
    app_id: str,
    app_version: str,
    build: str,
    artifact_name: str,
    platform: str,
) -> ScanResult:
    return ScanResult(
        scan_id=str(uuid.uuid4()),
        scanned_at=_utc_now_iso(),
        app_id=app_id,
        app_version=app_version,
        build=build,
        artifact_name=artifact_name,
        platform=platform,
    )


def _prepare_ios(bundle: IPABundle) -> tuple[ScanResult, CheckContext]:
    info = bundle.info_plist
    result = _new_result(
        app_id=info.get("CFBundleIdentifier", "unknown"),
        app_version=info.get("CFBundleShortVersionString", "unknown"),
        build=info.get("CFBundleVersion", "unknown"),
        artifact_name=bundle.ipa_path.name,
        platform="ios",
    )
    # One shared context — strings and binary are parsed lazily and cached.
    ctx = CheckContext(
        binary_path=bundle.binary_path,
        info_plist=bundle.info_plist,
        app_dir=bundle.app_dir,
    )
    return result, ctx


def _prepare_android(bundle: APKBundle) -> tuple[ScanResult, AndroidCheckContext]:
    result = _new_result(
        app_id=bundle.package_name,
        app_version=bundle.version_name,
        build=bundle.version_code,
        artifact_name=bundle.apk_path.name,
        platform="android",
    )
    # Reuse the APK object parsed during ingestion instead of parsing again.
    ctx = AndroidCheckContext(
        apk_path=bundle.apk_path,
        work_dir=bundle.work_dir,
        apk=bundle.apk,
    )
    return result, ctx


def _run_dynamic(
    app_id: str, platform: Platform, options: DynamicOptions
) -> list[Finding]:
    """Run on-device checks, never letting a failure abort the static scan."""
    try:
        from shingan.core.dynamic import run_dynamic_checks

        return run_dynamic_checks(
            bundle_id=app_id,
            device_udid=options.device_udid,
            timeout=options.timeout,
            platform=platform,
        )
    except Exception:
        logger.exception("Dynamic analysis failed — skipping")
        return []
