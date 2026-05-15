"""AND-SEC-010 / AND-SEC-016: Weak cryptographic algorithms and key management in Android APK.

Scans DEX strings for:
  - JCA/JCE API calls using known-weak algorithms (MASVS-CRYPTO-1):
    MD5, SHA-1, DES, 3DES, RC4, ECB mode, RSA/PKCS1v15
  - Hardcoded IV, salt, or key material (MASVS-CRYPTO-2)
"""

from __future__ import annotations

import re

from shingan.core.context import AndroidCheckContext
from shingan.core.models import Finding, Severity

# (rule_id_suffix, label, pattern, severity)
_WEAK_CRYPTO: list[tuple[str, str, re.Pattern, Severity]] = [
    (
        "md5",
        "MD5 hash",
        re.compile(r'MessageDigest\.getInstance\s*\(\s*["\']MD5["\']', re.IGNORECASE),
        Severity.HIGH,
    ),
    (
        "sha1",
        "SHA-1 hash",
        re.compile(
            r'MessageDigest\.getInstance\s*\(\s*["\']SHA-?1["\']', re.IGNORECASE
        ),
        Severity.MEDIUM,
    ),
    (
        "des",
        "DES cipher",
        re.compile(r'Cipher\.getInstance\s*\(\s*["\']DES[/"\']', re.IGNORECASE),
        Severity.HIGH,
    ),
    (
        "3des",
        "Triple-DES cipher",
        re.compile(r'Cipher\.getInstance\s*\(\s*["\']DESede', re.IGNORECASE),
        Severity.HIGH,
    ),
    (
        "rc4",
        "RC4 cipher",
        re.compile(r'Cipher\.getInstance\s*\(\s*["\']RC4["\']', re.IGNORECASE),
        Severity.HIGH,
    ),
    (
        "ecb",
        "ECB mode (any cipher)",
        re.compile(r'Cipher\.getInstance\s*\(\s*["\'][^"\']+/ECB/', re.IGNORECASE),
        Severity.HIGH,
    ),
    (
        "rsa_pkcs1",
        "RSA/PKCS1 padding",
        re.compile(
            r'Cipher\.getInstance\s*\(\s*["\']RSA/ECB/PKCS1Padding', re.IGNORECASE
        ),
        Severity.MEDIUM,
    ),
]


# Patterns indicating hardcoded IV / salt / key material (MASVS-CRYPTO-2)
_HARDCODED_KEY_PATTERNS: list[tuple[str, re.Pattern]] = [
    # e.g. byte[] iv = {0x00, 0x01, 0x02, ...}
    (
        "hardcoded byte array (IV/key candidate)",
        re.compile(
            r"(?:iv|IV|salt|SALT|key|KEY|nonce|NONCE)\s*[=:]\s*\{?\s*(?:0x|\\x)[0-9a-fA-F]{2}"
        ),
    ),
    # IvParameterSpec with literal
    (
        "IvParameterSpec with literal bytes",
        re.compile(r'new\s+IvParameterSpec\s*\(\s*(?:new\s+byte|["\'])'),
    ),
    # SecretKeySpec with literal string key
    (
        "SecretKeySpec with hardcoded key",
        re.compile(r'new\s+SecretKeySpec\s*\(\s*["\'][A-Za-z0-9+/=!@#$%^&*]{8,}["\']'),
    ),
    # PBEKeySpec with literal password
    (
        "PBEKeySpec with hardcoded password",
        re.compile(r'new\s+PBEKeySpec\s*\(\s*["\'][^"\']{4,}["\']\.toCharArray'),
    ),
]


def check(ctx: AndroidCheckContext) -> list[Finding]:
    findings: list[Finding] = []
    corpus = ctx.dex_strings

    # MASVS-CRYPTO-1: weak algorithms
    for suffix, label, pattern, severity in _WEAK_CRYPTO:
        hits = [s for s in corpus if pattern.search(s)]
        if hits:
            findings.append(
                Finding(
                    rule_id=f"AND-SEC-010-{suffix}",
                    title=f"Weak cryptography: {label} detected",
                    severity=severity,
                    description=(
                        f"The app uses {label} via the JCA/JCE API. "
                        "This algorithm is considered cryptographically weak and should not be "
                        "used for security-sensitive operations."
                    ),
                    evidence="\n".join(hits[:5]),
                    recommendation=(
                        "Replace weak algorithms with modern equivalents: "
                        "SHA-256/SHA-3 for hashing, AES-GCM for symmetric encryption, "
                        "RSA-OAEP or ECDH for asymmetric operations."
                    ),
                    masvs="MASVS-CRYPTO-1",
                )
            )

    # MASVS-CRYPTO-2: hardcoded IV / salt / key
    hardcoded_hits: list[str] = []
    for _label, pattern in _HARDCODED_KEY_PATTERNS:
        for s in corpus:
            if pattern.search(s):
                hardcoded_hits.append(s.strip()[:200])

    hardcoded_hits = list(dict.fromkeys(hardcoded_hits))
    if hardcoded_hits:
        findings.append(
            Finding(
                rule_id="AND-SEC-016",
                title="Hardcoded cryptographic key / IV / salt detected",
                severity=Severity.HIGH,
                description=(
                    f"{len(hardcoded_hits)} potential hardcoded key material string(s) found in DEX. "
                    "Hardcoded IVs, salts, or keys can be trivially extracted from the APK, "
                    "defeating the purpose of encryption."
                ),
                evidence="\n".join(hardcoded_hits[:10]),
                recommendation=(
                    "Generate IVs and salts randomly at runtime using SecureRandom. "
                    "Store long-lived keys in the Android Keystore, never in source code."
                ),
                masvs="MASVS-CRYPTO-2",
            )
        )

    return findings
