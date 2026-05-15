"""IOS-SEC-010 / IOS-SEC-016: Weak cryptography and key management issues.

Looks for:
  - Deprecated/weak algorithms: MD5, SHA1, DES, 3DES, RC4, ECB mode (MASVS-CRYPTO-1)
  - Hardcoded IV, salt, or encryption key candidates (MASVS-CRYPTO-2)
"""

from __future__ import annotations

import re

from shingan.core.context import CheckContext
from shingan.core.models import Finding, Severity

WEAK_CRYPTO: list[tuple[str, str, list[str], str]] = [
    (
        "IOS-SEC-010a",
        "MD5 usage detected",
        ["CC_MD5", "MD5_Init", "MD5_Update", "MD5Final", "CommonDigest/MD5"],
        "MD5 is cryptographically broken and must not be used for security purposes.",
    ),
    (
        "IOS-SEC-010b",
        "SHA-1 usage detected",
        [
            "CC_SHA1",
            "SHA1_Init",
            "SHA1_Update",
            "SecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1",
        ],
        "SHA-1 is deprecated for cryptographic use. Migrate to SHA-256 or higher.",
    ),
    (
        "IOS-SEC-010c",
        "DES / 3DES usage detected",
        ["kCCAlgorithmDES", "kCCAlgorithm3DES", "CCAlgorithmDES", "des_set_key"],
        "DES and 3DES are obsolete. Use AES-256 instead.",
    ),
    (
        "IOS-SEC-010d",
        "RC4 usage detected",
        ["kCCAlgorithmRC4", "RC4_set_key", "CCAlgorithmRC4"],
        "RC4 has known vulnerabilities. Use AES-256-GCM instead.",
    ),
    (
        "IOS-SEC-010e",
        "ECB mode usage detected",
        ["kCCOptionECBMode", "CCOptionECBMode"],
        "ECB mode leaks patterns in ciphertext. Use CBC or GCM mode.",
    ),
]

# Patterns indicating hardcoded IV / salt / key material (MASVS-CRYPTO-2)
_HARDCODED_KEY_PATTERNS: list[tuple[str, re.Pattern]] = [
    # e.g. let iv: [UInt8] = [0x00, 0x01, 0x02, ...]
    (
        "hardcoded byte array (IV/key candidate)",
        re.compile(
            r"(?:iv|IV|salt|SALT|key|KEY|nonce|NONCE)\s*[=:]\s*[\[\{]\s*0x[0-9a-fA-F]{2}"
        ),
    ),
    # e.g. kCCKeySize / CCCrypt with literal key string
    (
        "CCCrypt with literal key",
        re.compile(r"CCCrypt\s*\([^)]*[\"'][A-Za-z0-9+/=]{8,}[\"']"),
    ),
    # Static 16/24/32-char ASCII string assigned to variable named key/iv/salt
    (
        "hardcoded ASCII key/IV string",
        re.compile(
            r'(?:iv|IV|salt|key|nonce)\s*=\s*["\']([A-Za-z0-9+/=!@#$%^&*]{8,32})["\']'
        ),
    ),
]


def check(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    corpus = ctx.all_text

    # MASVS-CRYPTO-1: weak algorithms
    for rule_id, title, indicators, recommendation in WEAK_CRYPTO:
        hits = [ind for ind in indicators if any(ind in t for t in corpus)]
        if hits:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Weak cryptographic indicator(s) found: {', '.join(hits)}. "
                        "Using weak algorithms can allow attackers to recover plaintext "
                        "or forge signatures."
                    ),
                    evidence="\n".join(hits),
                    recommendation=recommendation,
                    extra={"indicators": hits},
                    masvs="MASVS-CRYPTO-1",
                )
            )

    # MASVS-CRYPTO-2: hardcoded IV / salt / key
    hardcoded_hits: list[str] = []
    for _label, pattern in _HARDCODED_KEY_PATTERNS:
        for s in corpus:
            if pattern.search(s):
                hardcoded_hits.append(s.strip()[:200])

    hardcoded_hits = list(dict.fromkeys(hardcoded_hits))  # deduplicate
    if hardcoded_hits:
        findings.append(
            Finding(
                rule_id="IOS-SEC-016",
                title="Hardcoded cryptographic key / IV / salt detected",
                severity=Severity.HIGH,
                description=(
                    f"{len(hardcoded_hits)} potential hardcoded key material string(s) found. "
                    "Hardcoded IVs, salts, or keys can be trivially extracted from the binary, "
                    "defeating the purpose of encryption."
                ),
                evidence="\n".join(hardcoded_hits[:10]),
                recommendation=(
                    "Generate IVs and salts randomly at runtime using SecRandomCopyBytes. "
                    "Store long-lived keys in the Keychain, never in source code or binary strings."
                ),
                masvs="MASVS-CRYPTO-2",
            )
        )

    return findings
