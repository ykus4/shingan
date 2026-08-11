"""Unit tests for the iOS checkers using synthetic inputs.

Model, diff, report, and suppression tests used to live here too; they now have
their own modules so this file covers only checkers.
"""

from __future__ import annotations

from shingan.core.checkers.ios import ats, metadata
from shingan.core.checkers.ios.crypto import check as check_crypto
from shingan.core.checkers.ios.debug_flags import check as check_debug
from shingan.core.checkers.ios.protection import check as check_protection
from shingan.core.checkers.ios.secrets import check as check_secrets
from shingan.core.constants import LSA_SCHEMES_THRESHOLD
from shingan.core.models import Severity

# ── Uniform checker interface ─────────────────────────────────────────────────


def test_ats_uses_the_context_interface(make_ios_ctx) -> None:
    """ats/metadata took a raw dict while every other checker took a context."""
    ctx = make_ios_ctx(
        info_plist={"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}
    )
    assert any(f.rule_id == "IOS-ATS-003a" for f in ats.check(ctx))


def test_metadata_uses_the_context_interface(make_ios_ctx) -> None:
    ctx = make_ios_ctx(info_plist={"UIBackgroundModes": ["voip"]})
    assert any(f.rule_id == "IOS-META-012a" for f in metadata.check(ctx))


# ── ATS checker ───────────────────────────────────────────────────────────────


def test_ats_clean() -> None:
    assert ats.check_plist({}) == []


def test_ats_arbitrary_loads() -> None:
    findings = ats.check_plist(
        {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}
    )
    assert any(f.rule_id == "IOS-ATS-003a" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_ats_arbitrary_loads_false() -> None:
    findings = ats.check_plist(
        {"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": False}}
    )
    assert not any(f.rule_id == "IOS-ATS-003a" for f in findings)


def test_ats_media_and_web_exceptions() -> None:
    findings = ats.check_plist(
        {
            "NSAppTransportSecurity": {
                "NSAllowsArbitraryLoadsForMedia": True,
                "NSAllowsArbitraryLoadsInWebContent": True,
            }
        }
    )
    ids = {f.rule_id for f in findings}
    assert {"IOS-ATS-003b", "IOS-ATS-003c"} <= ids


def test_ats_local_networking() -> None:
    findings = ats.check_plist(
        {"NSAppTransportSecurity": {"NSAllowsLocalNetworking": True}}
    )
    assert any(f.rule_id == "IOS-ATS-003d" for f in findings)


def test_ats_domain_http_exception() -> None:
    findings = ats.check_plist(
        {
            "NSAppTransportSecurity": {
                "NSExceptionDomains": {
                    "example.com": {"NSExceptionAllowsInsecureHTTPLoads": True}
                }
            }
        }
    )
    assert any(f.rule_id == "IOS-ATS-003e" for f in findings)
    assert any("example.com" in f.title for f in findings)


def test_ats_weak_tls() -> None:
    findings = ats.check_plist(
        {
            "NSAppTransportSecurity": {
                "NSExceptionDomains": {
                    "legacy.example.com": {"NSExceptionMinimumTLSVersion": "TLSv1.0"}
                }
            }
        }
    )
    assert any(f.rule_id == "IOS-ATS-003f" for f in findings)


def test_ats_modern_tls_is_clean() -> None:
    findings = ats.check_plist(
        {
            "NSAppTransportSecurity": {
                "NSExceptionDomains": {
                    "ok.example.com": {"NSExceptionMinimumTLSVersion": "TLSv1.3"}
                }
            }
        }
    )
    assert not any(f.rule_id == "IOS-ATS-003f" for f in findings)


def test_ats_file_sharing() -> None:
    findings = ats.check_plist({"UIFileSharingEnabled": True})
    assert any(f.rule_id == "IOS-ATS-003g" for f in findings)


def test_ats_schemes_threshold_boundary() -> None:
    """LSA_SCHEMES_THRESHOLD controls the finding boundary exactly."""
    at_limit = [f"s{i}" for i in range(LSA_SCHEMES_THRESHOLD)]
    assert not any(
        f.rule_id == "IOS-ATS-003h"
        for f in ats.check_plist({"LSApplicationQueriesSchemes": at_limit})
    )

    over = [f"s{i}" for i in range(LSA_SCHEMES_THRESHOLD + 1)]
    assert any(
        f.rule_id == "IOS-ATS-003h"
        for f in ats.check_plist({"LSApplicationQueriesSchemes": over})
    )


# ── Metadata checker ──────────────────────────────────────────────────────────


def test_metadata_background_mode_voip() -> None:
    findings = metadata.check_plist({"UIBackgroundModes": ["voip"]})
    voip = next(f for f in findings if f.rule_id == "IOS-META-012a")
    assert voip.severity == Severity.LOW


def test_metadata_unknown_background_mode_ignored() -> None:
    findings = metadata.check_plist({"UIBackgroundModes": ["unknown-mode"]})
    assert not any(f.rule_id == "IOS-META-012a" for f in findings)


def test_metadata_sensitive_permissions() -> None:
    findings = metadata.check_plist(
        {
            "NSCameraUsageDescription": "Take photos",
            "NSMicrophoneUsageDescription": "Record audio",
        }
    )
    meta_b = [f for f in findings if f.rule_id == "IOS-META-012b"]
    assert len(meta_b) == 1
    assert "Camera" in meta_b[0].evidence


def test_metadata_missing_ats() -> None:
    assert any(f.rule_id == "IOS-META-012c" for f in metadata.check_plist({}))


def test_metadata_ats_present_no_012c() -> None:
    findings = metadata.check_plist({"NSAppTransportSecurity": {}})
    assert not any(f.rule_id == "IOS-META-012c" for f in findings)


def test_metadata_custom_url_scheme() -> None:
    findings = metadata.check_plist(
        {"CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp"]}]}
    )
    assert any(f.rule_id == "IOS-URL-018a" for f in findings)


def test_metadata_no_universal_links() -> None:
    assert any(f.rule_id == "IOS-URL-018b" for f in metadata.check_plist({}))


# ── Crypto checker ────────────────────────────────────────────────────────────


def test_crypto_detects_md5(make_ios_ctx) -> None:
    ctx = make_ios_ctx(strings={"_CC_MD5", "something else"})
    assert any(f.rule_id == "IOS-SEC-010a" for f in check_crypto(ctx))


def test_crypto_clean(make_ios_ctx) -> None:
    ctx = make_ios_ctx(strings={"SomeRandomString", "OtherThing"})
    assert not any(f.rule_id.startswith("IOS-SEC-010") for f in check_crypto(ctx))


# ── Debug flags checker ───────────────────────────────────────────────────────


def test_debug_flags_assertions_enabled(make_ios_ctx) -> None:
    ctx = make_ios_ctx(strings=set(), info_plist={"NSAssertionsEnabled": True})
    assert any(f.rule_id == "IOS-DBG-004c" for f in check_debug(ctx))


def test_debug_flags_nslog(make_ios_ctx) -> None:
    ctx = make_ios_ctx(strings={"NSLog(@'hello world')"})
    assert any(f.rule_id == "IOS-DBG-004b" for f in check_debug(ctx))


# ── Protection (RASP) checker ─────────────────────────────────────────────────


def test_protection_reports_missing_jailbreak_detection(make_ios_ctx) -> None:
    ctx = make_ios_ctx(strings={"some_unrelated_string"})
    jb = [f for f in check_protection(ctx) if f.rule_id == "IOS-RASP-005a-missing"]
    assert len(jb) == 1
    assert jb[0].severity == Severity.MEDIUM


def test_protection_recognises_jailbreak_detection(make_ios_ctx) -> None:
    ctx = make_ios_ctx(strings={"/Applications/Cydia.app", "other"})
    jb = [f for f in check_protection(ctx) if f.rule_id == "IOS-RASP-005a-found"]
    assert len(jb) == 1
    assert jb[0].severity == Severity.INFO


# ── Secrets checker (iOS profile) ─────────────────────────────────────────────


def test_secrets_detects_aws_key(make_ios_ctx) -> None:
    ctx = make_ios_ctx(strings={"AKIAIOSFODNN7EXAMPLE"})
    findings = check_secrets(ctx)
    assert any(f.rule_id == "IOS-SEC-002-aws_key" for f in findings)
    assert all(f.rule_id.startswith("IOS-") for f in findings)


def test_secrets_uses_long_strings_only(make_ios_ctx) -> None:
    """Short strings are filtered out of the secrets corpus."""
    ctx = make_ios_ctx(strings={"short"})
    assert check_secrets(ctx) == []


def test_secrets_http_url_is_medium(make_ios_ctx) -> None:
    ctx = make_ios_ctx(strings={"http://insecure.example.com/api"})
    url_findings = [f for f in check_secrets(ctx) if f.rule_id.endswith("http_url")]
    assert len(url_findings) == 1
    assert url_findings[0].severity == Severity.MEDIUM


def test_secrets_clean_binary(make_ios_ctx) -> None:
    ctx = make_ios_ctx(strings={"CFBundleIdentifier", "UIApplicationMain"})
    assert check_secrets(ctx) == []
