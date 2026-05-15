"""AND-SIGN-014: APK signing scheme checks.

Checks:
  - AND-SIGN-014a: APK signed with v1 (JAR signing) only — v2/v3 not present
  - AND-SIGN-014b: APK not signed at all (no certificates)
"""

from __future__ import annotations

import logging

from shingan.core.context import AndroidCheckContext
from shingan.core.models import Finding, Severity

logger = logging.getLogger(__name__)


def check(ctx: AndroidCheckContext) -> list[Finding]:
    findings: list[Finding] = []
    apk = ctx.apk
    if apk is None:
        return findings

    # Check for certificates (basic signing)
    try:
        certs = apk.get_certificates()
        if not certs:
            findings.append(
                Finding(
                    rule_id="AND-SIGN-014b",
                    title="APK has no signing certificates",
                    severity=Severity.HIGH,
                    description=(
                        "No signing certificates were found in the APK. "
                        "An unsigned APK cannot be installed on production Android devices "
                        "and may indicate a tampered or stripped build artifact."
                    ),
                    evidence="No certificates found",
                    recommendation="Sign the APK with a proper release keystore before distribution.",
                    masvs="MASVS-RESILIENCE-3",
                )
            )
            return findings
    except Exception as exc:
        logger.debug("Certificate check failed: %s", exc)
        return findings

    # Check signing scheme version via META-INF contents
    # v2/v3 signatures are stored outside the ZIP central directory and not
    # accessible via androguard's APK class directly. We infer from META-INF:
    # - v1 only: META-INF/*.SF + *.RSA/DSA/EC present, no APK Sig Block marker
    # - v2/v3: androguard exposes is_signed_v2() / is_signed_v3() on newer versions
    v2_signed = _check_v2_or_v3(apk)

    if not v2_signed:
        findings.append(
            Finding(
                rule_id="AND-SIGN-014a",
                title="APK uses v1 (JAR) signing only — v2/v3 scheme not detected",
                severity=Severity.MEDIUM,
                description=(
                    "The APK appears to be signed with the v1 JAR signing scheme only. "
                    "APK Signature Scheme v2/v3 (introduced in Android 7.0/8.0) provides "
                    "stronger integrity protection covering the entire archive, not just individual "
                    "files. v1-only APKs are vulnerable to the Janus vulnerability (CVE-2017-13156), "
                    "which allows bytecode injection without invalidating the signature."
                ),
                evidence="APK Signature Scheme v2/v3 not detected",
                recommendation=(
                    "Sign the APK with v2 or v3 signing scheme in addition to v1. "
                    "In Android Studio / Gradle: use `v2SigningEnabled true` in the signing config."
                ),
                masvs="MASVS-RESILIENCE-3",
            )
        )

    return findings


def _check_v2_or_v3(apk) -> bool:
    """Return True if the APK has v2 or v3 signing scheme."""
    # androguard >= 3.4 exposes is_signed_v2() / is_signed_v3()
    for method_name in ("is_signed_v2", "is_signed_v3"):
        try:
            method = getattr(apk, method_name, None)
            if callable(method) and method():
                return True
        except Exception:
            pass

    # Fallback: check META-INF for APK Sig Block indicator files
    # (not conclusive, but better than nothing)
    try:
        names = apk.get_files()
        # v2/v3 signed APKs typically still have META-INF/MANIFEST.MF
        # but the real check needs binary parsing of the APK Signing Block.
        # Without that, we conservatively return False so the finding fires.
        _ = names
    except Exception:
        pass

    return False
