"""Unit tests for Android checkers using synthetic inputs."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

from shingan.core.checkers.android import (
    crypto,
    debug_flags,
    manifest,
    permissions,
    protection,
    sbom,
    signing,
)
from shingan.core.context import AndroidCheckContext
from shingan.core.models import Severity

# ── Helpers ───────────────────────────────────────────────────────────────────


def _make_ctx(
    dex_strings: set[str] | None = None,
    native_strings: set[str] | None = None,
    apk_mock: MagicMock | None = None,
) -> AndroidCheckContext:
    """Build an AndroidCheckContext with pre-populated data (no file I/O needed)."""
    ctx = AndroidCheckContext(apk_path=Path("/dev/null"), work_dir=Path("/dev/null"))
    # Bypass lazy properties by injecting cached values directly
    ctx.__dict__["dex_strings"] = dex_strings or set()
    ctx.__dict__["strings"] = native_strings or set()
    ctx.__dict__["symbol_names"] = set()
    ctx.__dict__["all_text"] = (dex_strings or set()) | (native_strings or set())
    ctx.__dict__["native_binaries"] = []
    ctx.__dict__["apk"] = apk_mock
    return ctx


def _make_apk_mock(**attrs) -> MagicMock:
    """Return a MagicMock that responds to common androguard APK method calls."""
    apk = MagicMock()
    apk.get_package.return_value = attrs.get("package", "com.example.app")
    apk.get_androidversion_name.return_value = attrs.get("version_name", "1.0")
    apk.get_androidversion_code.return_value = attrs.get("version_code", "1")
    apk.get_min_sdk_version.return_value = attrs.get("min_sdk", "28")
    apk.get_target_sdk_version.return_value = attrs.get("target_sdk", "34")
    apk.get_permissions.return_value = attrs.get("permissions", [])
    apk.get_certificates.return_value = attrs.get("certificates", [MagicMock()])
    apk.get_attribute_value.return_value = attrs.get("attribute_value")
    apk.get_android_manifest_xml.return_value = None
    return apk


# ── debug_flags ───────────────────────────────────────────────────────────────


def test_debug_flags_debuggable_true():
    apk = _make_apk_mock()
    apk.get_attribute_value.return_value = "true"
    ctx = _make_ctx(apk_mock=apk)
    findings = debug_flags.check(ctx)
    assert any(f.rule_id == "AND-DBG-004a" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_debug_flags_debuggable_false():
    apk = _make_apk_mock()
    apk.get_attribute_value.return_value = "false"
    ctx = _make_ctx(apk_mock=apk)
    findings = debug_flags.check(ctx)
    assert not any(f.rule_id == "AND-DBG-004a" for f in findings)


def test_debug_flags_log_calls_detected():
    ctx = _make_ctx(dex_strings={"Log.d(TAG, message)", "some other string"})
    findings = debug_flags.check(ctx)
    assert any(f.rule_id == "AND-DBG-004b" for f in findings)
    assert any(f.severity == Severity.LOW for f in findings)


def test_debug_flags_no_log_calls():
    ctx = _make_ctx(dex_strings={"SomeClass.doSomething()", "another string"})
    findings = debug_flags.check(ctx)
    assert not any(f.rule_id == "AND-DBG-004b" for f in findings)


# ── crypto ────────────────────────────────────────────────────────────────────


def test_crypto_detects_md5():
    ctx = _make_ctx(dex_strings={'MessageDigest.getInstance("MD5")'})
    findings = crypto.check(ctx)
    assert any(f.rule_id == "AND-SEC-010-md5" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_crypto_detects_ecb():
    ctx = _make_ctx(dex_strings={'Cipher.getInstance("AES/ECB/PKCS5Padding")'})
    findings = crypto.check(ctx)
    assert any(f.rule_id == "AND-SEC-010-ecb" for f in findings)


def test_crypto_detects_des():
    ctx = _make_ctx(dex_strings={'Cipher.getInstance("DES/CBC/PKCS5Padding")'})
    findings = crypto.check(ctx)
    assert any(f.rule_id == "AND-SEC-010-des" for f in findings)


def test_crypto_clean():
    ctx = _make_ctx(dex_strings={'Cipher.getInstance("AES/GCM/NoPadding")'})
    findings = crypto.check(ctx)
    assert not any(f.rule_id.startswith("AND-SEC-010") for f in findings)


# ── protection ────────────────────────────────────────────────────────────────


def test_protection_root_detected():
    ctx = _make_ctx(native_strings={"/system/xbin/su", "other"})
    findings = protection.check(ctx)
    assert any(f.rule_id == "AND-RASP-005a-found" for f in findings)
    assert any(f.severity == Severity.INFO for f in findings)


def test_protection_no_root_detection():
    ctx = _make_ctx(dex_strings={"unrelated string"})
    findings = protection.check(ctx)
    assert any(f.rule_id == "AND-RASP-005a-missing" for f in findings)
    assert any(f.severity == Severity.MEDIUM for f in findings)


def test_protection_frida_detected():
    ctx = _make_ctx(dex_strings={"XposedBridge", "frida-agent"})
    findings = protection.check(ctx)
    assert any(f.rule_id == "AND-RASP-005b-found" for f in findings)


def test_protection_ssl_pinning_detected():
    ctx = _make_ctx(dex_strings={"CertificatePinner", "okhttp3.CertificatePinner"})
    findings = protection.check(ctx)
    assert any(f.rule_id == "AND-RASP-005d-found" for f in findings)


def test_protection_no_ssl_pinning():
    ctx = _make_ctx(dex_strings={"some.package.SomeClass"})
    findings = protection.check(ctx)
    assert any(f.rule_id == "AND-RASP-005d-missing" for f in findings)


# ── manifest ─────────────────────────────────────────────────────────────────


def test_manifest_allow_backup_true():
    apk = _make_apk_mock()
    apk.get_attribute_value.return_value = "true"
    ctx = _make_ctx(apk_mock=apk)
    findings = manifest.check(ctx)
    assert any(f.rule_id == "AND-META-013a" for f in findings)
    assert any(f.severity == Severity.MEDIUM for f in findings)


def test_manifest_allow_backup_false():
    apk = _make_apk_mock()
    apk.get_attribute_value.return_value = "false"
    ctx = _make_ctx(apk_mock=apk)
    findings = manifest.check(ctx)
    assert not any(f.rule_id == "AND-META-013a" for f in findings)


def test_manifest_min_sdk_too_low():
    apk = _make_apk_mock(min_sdk="19")
    apk.get_attribute_value.return_value = "false"
    ctx = _make_ctx(apk_mock=apk)
    findings = manifest.check(ctx)
    assert any(f.rule_id == "AND-SDK-015" for f in findings)
    assert any(f.severity == Severity.LOW for f in findings)


def test_manifest_min_sdk_ok():
    apk = _make_apk_mock(min_sdk="28")
    apk.get_attribute_value.return_value = "false"
    ctx = _make_ctx(apk_mock=apk)
    findings = manifest.check(ctx)
    assert not any(f.rule_id == "AND-SDK-015" for f in findings)


# ── permissions ───────────────────────────────────────────────────────────────


def test_permissions_sms():
    apk = _make_apk_mock(permissions=["android.permission.SEND_SMS"])
    ctx = _make_ctx(apk_mock=apk)
    findings = permissions.check(ctx)
    assert any(f.rule_id == "AND-META-012-high" for f in findings)
    assert any("SEND_SMS" in f.evidence for f in findings)


def test_permissions_none():
    apk = _make_apk_mock(permissions=[])
    ctx = _make_ctx(apk_mock=apk)
    findings = permissions.check(ctx)
    assert findings == []


def test_permissions_medium():
    apk = _make_apk_mock(permissions=["android.permission.CAMERA"])
    ctx = _make_ctx(apk_mock=apk)
    findings = permissions.check(ctx)
    assert any(f.rule_id == "AND-META-012-medium" for f in findings)


# ── sbom ─────────────────────────────────────────────────────────────────────


def test_sbom_detects_firebase():
    ctx = _make_ctx(dex_strings={"com.google.firebase.FirebaseApp"})
    findings = sbom.check(ctx)
    assert any(f.rule_id == "AND-DEP-011" for f in findings)
    assert any("Firebase" in f.evidence for f in findings)


def test_sbom_detects_okhttp():
    ctx = _make_ctx(dex_strings={"com.squareup.okhttp3.OkHttpClient"})
    findings = sbom.check(ctx)
    assert any(f.rule_id == "AND-DEP-011" for f in findings)


def test_sbom_clean():
    ctx = _make_ctx(dex_strings={"com.example.myapp.MainActivity"})
    findings = sbom.check(ctx)
    assert findings == []


# ── signing ───────────────────────────────────────────────────────────────────


def test_signing_no_certificates():
    apk = _make_apk_mock(certificates=[])
    ctx = _make_ctx(apk_mock=apk)
    findings = signing.check(ctx)
    assert any(f.rule_id == "AND-SIGN-014b" for f in findings)
    assert any(f.severity == Severity.HIGH for f in findings)


def test_signing_v1_only():
    apk = _make_apk_mock()
    # Simulate no v2/v3 methods available
    del apk.is_signed_v2
    del apk.is_signed_v3
    ctx = _make_ctx(apk_mock=apk)
    findings = signing.check(ctx)
    assert any(f.rule_id == "AND-SIGN-014a" for f in findings)


def test_signing_v2_signed():
    apk = _make_apk_mock()
    apk.is_signed_v2.return_value = True
    ctx = _make_ctx(apk_mock=apk)
    findings = signing.check(ctx)
    assert not any(f.rule_id == "AND-SIGN-014a" for f in findings)
