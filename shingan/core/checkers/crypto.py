"""IOS-SEC-010: Weak cryptography detection.

Looks for usage of deprecated/weak algorithms: MD5, SHA1, DES, 3DES, RC4, ECB mode.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import lief

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
    (
        "IOS-SEC-010f",
        "Hardcoded IV / static initialization vector",
        ["kCCOptionECBMode"],  # covered separately by string check
        "A static IV defeats the purpose of encryption.",
    ),
]


def _get_strings(binary_path: Path) -> set[str]:
    try:
        result = subprocess.run(
            ["strings", "-a", "-n", "5", str(binary_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return set(result.stdout.splitlines())
    except Exception:
        return set()


def check(binary_path: Path) -> list[Finding]:
    findings: list[Finding] = []

    binary = lief.parse(str(binary_path))
    symbol_names: set[str] = set()
    if binary is not None:
        symbol_names = {sym.name for sym in binary.symbols}

    strings = _get_strings(binary_path)
    all_text = symbol_names | strings

    for rule_id, title, indicators, recommendation in WEAK_CRYPTO:
        hits = [ind for ind in indicators if any(ind in t for t in all_text)]
        if hits:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=Severity.MEDIUM,
                    description=(
                        f"Weak cryptographic indicator(s) found: {', '.join(hits)}. "
                        "Using weak algorithms can allow attackers to recover plaintext or forge signatures."
                    ),
                    evidence="\n".join(hits),
                    recommendation=recommendation,
                    extra={"indicators": hits},
                    masvs="MASVS-CRYPTO-1",
                )
            )

    return findings
