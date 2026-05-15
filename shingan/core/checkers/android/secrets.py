"""AND-SEC-002: Hardcoded secrets and sensitive strings in Android APK.

Reuses the SECRET_PATTERNS and _shannon_entropy from the iOS secrets checker,
applying them to DEX strings and native library strings.
Rule IDs use the AND- prefix instead of IOS-.
"""

from __future__ import annotations

import logging

from shingan.core.binary import AndroidCheckContext
from shingan.core.checkers.secrets import SECRET_PATTERNS, _shannon_entropy
from shingan.core.constants import (
    ENTROPY_MIN_LEN,
    ENTROPY_SAMPLE_SIZE,
    ENTROPY_THRESHOLD,
    SECRETS_MAX_HITS_PER_PATTERN,
)
from shingan.core.models import Finding, Severity

logger = logging.getLogger(__name__)

_ENTROPY_FALSE_POSITIVE_PREFIXES = ("https://", "http://", "com.", "org.", "eyJ")


def check(ctx: AndroidCheckContext) -> list[Finding]:
    findings: list[Finding] = []

    # Combine DEX strings with native .so strings for comprehensive coverage
    strings = list(ctx.dex_strings | ctx.strings)

    # Pattern matching (same patterns as iOS, AND- prefix)
    matched: dict[str, list[str]] = {}
    for line in strings:
        for suffix, _label, pattern in SECRET_PATTERNS:
            m = pattern.search(line)
            if m:
                bucket = matched.setdefault(suffix, [])
                if len(bucket) < SECRETS_MAX_HITS_PER_PATTERN:
                    bucket.append(line.strip()[:200])

    for suffix, label, _ in SECRET_PATTERNS:
        hits = matched.get(suffix)
        if not hits:
            continue
        is_url = suffix in ("http_url", "endpoint")
        findings.append(
            Finding(
                rule_id=f"AND-SEC-002-{suffix}",
                title=f"Hardcoded {label} found",
                severity=Severity.HIGH if not is_url else Severity.MEDIUM,
                description=(
                    f"{len(hits)} instance(s) of {label} detected in the APK string table. "
                    "Hardcoded credentials can be trivially extracted with tools like `apktool` or `jadx`."
                ),
                evidence="\n".join(hits[:5]),
                recommendation=(
                    "Move secrets to a secure vault (e.g. Android Keystore, environment variables). "
                    "Never embed credentials in source code or APK assets."
                ),
                extra={"match_count": len(hits)},
                masvs="MASVS-NETWORK-1" if is_url else "MASVS-STORAGE-2",
            )
        )

    # High-entropy strings
    high_entropy = [
        s.strip()[:200]
        for line in strings
        if (
            len((s := line.strip())) >= ENTROPY_MIN_LEN
            and _shannon_entropy(s) >= ENTROPY_THRESHOLD
            and not any(s.startswith(fp) for fp in _ENTROPY_FALSE_POSITIVE_PREFIXES)
        )
    ]
    if high_entropy:
        findings.append(
            Finding(
                rule_id="AND-SEC-002-entropy",
                title="High-entropy strings detected (possible encoded secrets)",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(high_entropy)} string(s) with Shannon entropy ≥ {ENTROPY_THRESHOLD:.1f} found. "
                    "These may be base64-encoded keys, encrypted blobs, or embedded certificates."
                ),
                evidence="\n".join(high_entropy[:ENTROPY_SAMPLE_SIZE]),
                recommendation=(
                    "Review each high-entropy string manually. "
                    "Secrets should not be baked into the APK."
                ),
                extra={"total_high_entropy": len(high_entropy)},
                masvs="MASVS-STORAGE-2",
            )
        )

    return findings
