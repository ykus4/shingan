"""IOS-SEC-002: Hardcoded secrets and sensitive strings.

Extracts printable strings from the binary and runs:
  - Regex patterns for known secret formats (API keys, tokens, URLs)
  - Shannon entropy filter to surface high-entropy encoded blobs
"""

from __future__ import annotations

import math
import re
import subprocess
from pathlib import Path

from shingan.core.models import Finding, Severity


# (rule_id_suffix, label, pattern)
SECRET_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("aws_key", "AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    (
        "aws_secret",
        "AWS Secret (candidate)",
        re.compile(r"(?i)aws.{0,20}secret.{0,5}['\"]([A-Za-z0-9/+=]{40})"),
    ),
    ("gcp_key", "Google API Key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    ("stripe", "Stripe API Key", re.compile(r"sk_(live|test)_[0-9A-Za-z]{16,}")),
    ("github_pat", "GitHub PAT", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    ("slack", "Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    ("firebase", "Firebase URL", re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com")),
    ("apns_key", "APNs Auth Key candidate", re.compile(r"-----BEGIN PRIVATE KEY-----")),
    (
        "jwt",
        "JWT token",
        re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+"),
    ),
    (
        "generic_key",
        "Generic 'key/secret/token'",
        re.compile(
            r"(?i)(api_key|apikey|secret_key|access_token|auth_token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})"
        ),
    ),
    (
        "http_url",
        "Plain HTTP URL (non-localhost)",
        re.compile(
            r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}"
        ),
    ),
    (
        "endpoint",
        "Hardcoded endpoint/path",
        re.compile(r"/api/v\d+/[a-zA-Z0-9/_\-]{5,}"),
    ),
]

ENTROPY_THRESHOLD = 4.2  # bits per character — typical for base64/hex secrets
ENTROPY_MIN_LEN = 20  # ignore short strings


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    length = len(s)
    return -sum((f / length) * math.log2(f / length) for f in freq.values())


def _extract_strings(binary_path: Path) -> list[str]:
    """Use `strings` to pull printable sequences from the binary."""
    try:
        result = subprocess.run(
            ["strings", "-a", "-n", "8", str(binary_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return result.stdout.splitlines()
    except Exception:
        return []


def check(binary_path: Path) -> list[Finding]:
    findings: list[Finding] = []
    strings = _extract_strings(binary_path)

    # --- Pattern matching ---
    matched: dict[str, list[str]] = {}
    for line in strings:
        for suffix, label, pattern in SECRET_PATTERNS:
            m = pattern.search(line)
            if m:
                matched.setdefault(suffix, [])
                if len(matched[suffix]) < 10:
                    matched[suffix].append(line.strip()[:200])

    for suffix, label, _ in SECRET_PATTERNS:
        hits = matched.get(suffix)
        if not hits:
            continue
        is_url = suffix in ("http_url", "endpoint")
        findings.append(
            Finding(
                rule_id=f"IOS-SEC-002-{suffix}",
                title=f"Hardcoded {label} found",
                severity=Severity.HIGH if not is_url else Severity.MEDIUM,
                description=(
                    f"{len(hits)} instance(s) of {label} detected in the binary string table. "
                    "Hardcoded credentials can be trivially extracted with tools like `strings`."
                ),
                evidence="\n".join(hits[:5]),
                recommendation=(
                    "Move secrets to a secure vault (e.g. iOS Keychain, AWS Secrets Manager). "
                    "Never embed credentials in source code or binary assets."
                ),
                extra={"match_count": len(hits)},
            )
        )

    # --- High-entropy strings ---
    high_entropy = []
    for line in strings:
        s = line.strip()
        if len(s) >= ENTROPY_MIN_LEN and _shannon_entropy(s) >= ENTROPY_THRESHOLD:
            # Skip common false positives
            if not any(
                s.startswith(fp)
                for fp in ("https://", "http://", "com.", "org.", "eyJ")
            ):
                high_entropy.append(s[:200])
    if high_entropy:
        sample = high_entropy[:10]
        findings.append(
            Finding(
                rule_id="IOS-SEC-002-entropy",
                title="High-entropy strings detected (possible encoded secrets)",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(high_entropy)} string(s) with Shannon entropy ≥ {ENTROPY_THRESHOLD:.1f} found. "
                    "These may be base64-encoded keys, encrypted blobs, or embedded certificates."
                ),
                evidence="\n".join(sample),
                recommendation=(
                    "Review each high-entropy string manually. Secrets should not be baked into the binary."
                ),
                extra={"total_high_entropy": len(high_entropy)},
            )
        )

    return findings
