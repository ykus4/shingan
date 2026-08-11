"""Shared secret-detection engine for iOS and Android.

The iOS and Android secrets checkers were near-verbatim copies of one another:
identical regex table, identical entropy filter, identical false-positive
prefixes, differing only in rule-ID prefix, corpus, and a few wording details.
The detection logic lives here once; the platform modules supply a
:class:`SecretsProfile` describing the differences.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from shingan.core.constants import (
    ENTROPY_SAMPLE_SIZE,
    ENTROPY_THRESHOLD,
    EVIDENCE_LINE_MAX_LEN,
    SECRETS_EVIDENCE_SAMPLE,
    SECRETS_MAX_HITS_PER_PATTERN,
)
from shingan.core.entropy import is_high_entropy_candidate
from shingan.core.models import Finding, Severity


@dataclass(frozen=True)
class SecretPattern:
    """One secret format to look for."""

    #: Appended to the rule ID, e.g. ``aws_key`` → ``IOS-SEC-002-aws_key``.
    suffix: str
    #: Human-readable name used in the finding title.
    label: str
    pattern: re.Pattern[str]
    #: URL/endpoint hits are informational rather than credential leaks.
    is_url: bool = False

    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM if self.is_url else Severity.HIGH

    @property
    def masvs(self) -> str:
        return "MASVS-NETWORK-1" if self.is_url else "MASVS-STORAGE-2"


#: Secret formats scanned on every platform.
SECRET_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("aws_key", "AWS Access Key ID", re.compile(r"AKIA[0-9A-Z]{16}")),
    SecretPattern(
        "aws_secret",
        "AWS Secret (candidate)",
        re.compile(r"(?i)aws.{0,20}secret.{0,5}['\"]([A-Za-z0-9/+=]{40})"),
    ),
    SecretPattern("gcp_key", "Google API Key", re.compile(r"AIza[0-9A-Za-z_\-]{35}")),
    SecretPattern(
        "stripe", "Stripe API Key", re.compile(r"sk_(live|test)_[0-9A-Za-z]{16,}")
    ),
    SecretPattern("github_pat", "GitHub PAT", re.compile(r"ghp_[A-Za-z0-9]{36}")),
    SecretPattern("slack", "Slack token", re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")),
    SecretPattern(
        "firebase",
        "Firebase URL",
        re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"),
    ),
    SecretPattern(
        "apns_key",
        "APNs Auth Key candidate",
        re.compile(r"-----BEGIN PRIVATE KEY-----"),
    ),
    SecretPattern(
        "jwt",
        "JWT token",
        re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]+"),
    ),
    SecretPattern(
        "generic_key",
        "Generic 'key/secret/token'",
        re.compile(
            r"(?i)(api_key|apikey|secret_key|access_token|auth_token)\s*[=:]\s*['\"]?([A-Za-z0-9_\-]{16,})"
        ),
    ),
    SecretPattern(
        "http_url",
        "Plain HTTP URL (non-localhost)",
        re.compile(
            r"http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}"
        ),
        is_url=True,
    ),
    SecretPattern(
        "endpoint",
        "Hardcoded endpoint/path",
        re.compile(r"/api/v\d+/[a-zA-Z0-9/_\-]{5,}"),
        is_url=True,
    ),
)


@dataclass(frozen=True)
class SecretsProfile:
    """Platform-specific wording and rule-ID prefix for the secrets scan."""

    #: e.g. ``IOS-SEC-002`` or ``AND-SEC-002``.
    rule_base: str
    #: Where the strings came from, e.g. "the binary string table".
    corpus_label: str
    #: Tools an attacker would use, e.g. "`strings`" or "`apktool` or `jadx`".
    extraction_tools: str
    #: Recommended secure storage, e.g. "iOS Keychain".
    secure_storage: str
    #: Artifact noun used in recommendations, e.g. "binary" or "APK".
    artifact_noun: str


def _collect_matches(corpus: set[str]) -> dict[str, list[str]]:
    """Map pattern suffix → capped list of matching lines."""
    matched: dict[str, list[str]] = {}
    for line in corpus:
        stripped = line.strip()
        if not stripped:
            continue
        for spec in SECRET_PATTERNS:
            if not spec.pattern.search(line):
                continue
            bucket = matched.setdefault(spec.suffix, [])
            if len(bucket) < SECRETS_MAX_HITS_PER_PATTERN:
                bucket.append(stripped[:EVIDENCE_LINE_MAX_LEN])
    return matched


def scan_secrets(corpus: set[str], profile: SecretsProfile) -> list[Finding]:
    """Run pattern and entropy detection over ``corpus``."""
    findings: list[Finding] = []
    matched = _collect_matches(corpus)

    for spec in SECRET_PATTERNS:
        hits = matched.get(spec.suffix)
        if not hits:
            continue
        findings.append(
            Finding(
                rule_id=f"{profile.rule_base}-{spec.suffix}",
                title=f"Hardcoded {spec.label} found",
                severity=spec.severity,
                description=(
                    f"{len(hits)} instance(s) of {spec.label} detected in "
                    f"{profile.corpus_label}. Hardcoded credentials can be "
                    f"trivially extracted with tools like {profile.extraction_tools}."
                ),
                evidence="\n".join(hits[:SECRETS_EVIDENCE_SAMPLE]),
                recommendation=(
                    f"Move secrets to a secure vault (e.g. {profile.secure_storage}). "
                    "Never embed credentials in source code or "
                    f"{profile.artifact_noun} assets."
                ),
                extra={"match_count": len(hits)},
                masvs=spec.masvs,
            )
        )

    high_entropy = sorted(
        {
            stripped[:EVIDENCE_LINE_MAX_LEN]
            for line in corpus
            if is_high_entropy_candidate(stripped := line.strip())
        }
    )
    if high_entropy:
        findings.append(
            Finding(
                rule_id=f"{profile.rule_base}-entropy",
                title="High-entropy strings detected (possible encoded secrets)",
                severity=Severity.MEDIUM,
                description=(
                    f"{len(high_entropy)} string(s) with Shannon entropy "
                    f"≥ {ENTROPY_THRESHOLD:.1f} found. These may be base64-encoded "
                    "keys, encrypted blobs, or embedded certificates."
                ),
                evidence="\n".join(high_entropy[:ENTROPY_SAMPLE_SIZE]),
                recommendation=(
                    "Review each high-entropy string manually. Secrets should not "
                    f"be baked into the {profile.artifact_noun}."
                ),
                extra={"total_high_entropy": len(high_entropy)},
                masvs="MASVS-STORAGE-2",
            )
        )

    return findings
