"""AND-SEC-010: Weak cryptographic algorithms in Android APK.

Scans DEX strings for JCA/JCE API calls using known-weak algorithms:
  - MD5, SHA-1 message digests
  - DES, 3DES, RC4, RC2 ciphers
  - ECB mode (any cipher)
  - RSA with PKCS1v15 padding
"""

from __future__ import annotations

import re

from shingan.core.binary import AndroidCheckContext
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


def check(ctx: AndroidCheckContext) -> list[Finding]:
    findings: list[Finding] = []
    corpus = ctx.dex_strings

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

    return findings
