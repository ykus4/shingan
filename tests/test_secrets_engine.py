"""Tests for the shared secret-detection engine.

The iOS and Android secrets checkers were near-verbatim copies; these tests
cover the single engine both now delegate to.
"""

from __future__ import annotations

import pytest

from shingan.core.checkers.android.secrets import check as check_android
from shingan.core.checkers.common.secrets_engine import (
    SECRET_PATTERNS,
    SecretsProfile,
    scan_secrets,
)
from shingan.core.checkers.ios.secrets import check as check_ios
from shingan.core.constants import SECRETS_MAX_HITS_PER_PATTERN
from shingan.core.models import Severity

PROFILE = SecretsProfile(
    rule_base="TEST-SEC",
    corpus_label="the test corpus",
    extraction_tools="`strings`",
    secure_storage="a vault",
    artifact_noun="artifact",
)


@pytest.mark.parametrize(
    ("suffix", "sample"),
    [
        ("aws_key", "AKIAIOSFODNN7EXAMPLE"),
        ("gcp_key", "AIzaSyA1234567890123456789012345678901234"),
        ("stripe", "sk_live_0123456789abcdefghij"),
        ("github_pat", "ghp_" + "a" * 36),
        ("slack", "xoxb-0123456789-abcdefg"),
        ("firebase", "https://myapp-1234.firebaseio.com"),
        ("apns_key", "-----BEGIN PRIVATE KEY-----"),
        ("http_url", "http://insecure.example.com/path"),
        ("endpoint", "/api/v2/users/profile"),
    ],
)
def test_each_pattern_matches_its_sample(suffix: str, sample: str) -> None:
    findings = scan_secrets({sample}, PROFILE)
    assert any(f.rule_id == f"TEST-SEC-{suffix}" for f in findings)


def test_rule_ids_use_the_profile_prefix() -> None:
    findings = scan_secrets({"AKIAIOSFODNN7EXAMPLE"}, PROFILE)
    assert all(f.rule_id.startswith("TEST-SEC") for f in findings)


def test_credentials_are_high_and_urls_are_medium() -> None:
    findings = scan_secrets(
        {"AKIAIOSFODNN7EXAMPLE", "http://insecure.example.com/x"}, PROFILE
    )
    by_id = {f.rule_id: f for f in findings}
    assert by_id["TEST-SEC-aws_key"].severity == Severity.HIGH
    assert by_id["TEST-SEC-http_url"].severity == Severity.MEDIUM


def test_masvs_mapping() -> None:
    findings = scan_secrets(
        {"AKIAIOSFODNN7EXAMPLE", "http://insecure.example.com/x"}, PROFILE
    )
    by_id = {f.rule_id: f for f in findings}
    assert by_id["TEST-SEC-aws_key"].masvs == "MASVS-STORAGE-2"
    assert by_id["TEST-SEC-http_url"].masvs == "MASVS-NETWORK-1"


def test_clean_corpus_yields_nothing() -> None:
    assert scan_secrets({"CFBundleIdentifier", "UIApplicationMain"}, PROFILE) == []


def test_empty_corpus() -> None:
    assert scan_secrets(set(), PROFILE) == []


def test_hits_are_capped_per_pattern() -> None:
    corpus = {f"AKIA{i:016d}" for i in range(SECRETS_MAX_HITS_PER_PATTERN + 10)}
    finding = next(f for f in scan_secrets(corpus, PROFILE) if "aws_key" in f.rule_id)
    assert finding.extra["match_count"] == SECRETS_MAX_HITS_PER_PATTERN


def test_entropy_finding_is_reported() -> None:
    findings = scan_secrets({"aB3xQ9mKvP2nLwRjTyUoIeWsZdHfCgA1"}, PROFILE)
    assert any(f.rule_id == "TEST-SEC-entropy" for f in findings)


def test_entropy_evidence_is_deterministic() -> None:
    """Evidence is sorted, so repeated scans of a set produce identical output."""
    corpus = {
        "aB3xQ9mKvP2nLwRjTyUoIeWsZdHfCgA1",
        "zZ9yX8wV7uT6sR5qP4oN3mL2kJ1hG0fE",
    }
    first = scan_secrets(corpus, PROFILE)
    second = scan_secrets(corpus, PROFILE)
    assert [f.evidence for f in first] == [f.evidence for f in second]


def test_pattern_table_has_unique_suffixes() -> None:
    suffixes = [p.suffix for p in SECRET_PATTERNS]
    assert len(suffixes) == len(set(suffixes))


# ── Platform adapters ─────────────────────────────────────────────────────────


def test_ios_adapter_uses_ios_prefix(make_ios_ctx) -> None:
    ctx = make_ios_ctx(strings={"AKIAIOSFODNN7EXAMPLE"})
    findings = check_ios(ctx)
    assert findings
    assert all(f.rule_id.startswith("IOS-SEC-002") for f in findings)


def test_android_adapter_uses_and_prefix(make_android_ctx) -> None:
    ctx = make_android_ctx(dex_strings={"AKIAIOSFODNN7EXAMPLE"})
    findings = check_android(ctx)
    assert findings
    assert all(f.rule_id.startswith("AND-SEC-002") for f in findings)


def test_android_scans_both_dex_and_native(make_android_ctx) -> None:
    ctx = make_android_ctx(
        dex_strings={"AKIAIOSFODNN7EXAMPLE"},
        native_strings={"ghp_" + "b" * 36},
    )
    ids = {f.rule_id for f in check_android(ctx)}
    assert "AND-SEC-002-aws_key" in ids
    assert "AND-SEC-002-github_pat" in ids


def test_both_platforms_share_the_same_detections(
    make_ios_ctx, make_android_ctx
) -> None:
    """The two checkers must not drift apart in what they detect."""
    sample = {"AKIAIOSFODNN7EXAMPLE", "http://insecure.example.com/x"}
    ios_suffixes = {
        f.rule_id.removeprefix("IOS-SEC-002-")
        for f in check_ios(make_ios_ctx(strings=sample))
    }
    and_suffixes = {
        f.rule_id.removeprefix("AND-SEC-002-")
        for f in check_android(make_android_ctx(dex_strings=sample))
    }
    assert ios_suffixes == and_suffixes
