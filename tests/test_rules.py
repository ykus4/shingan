"""Tests for the custom YAML rule engine."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest
import yaml

from shingan.core.models import Severity
from shingan.core.rules import apply_custom_rules, load_rules


@pytest.fixture
def rules_dir(tmp_path: Path) -> Path:
    d = tmp_path / "rules"
    d.mkdir()
    return d


def write_rule(rules_dir: Path, rule: object, name: str = "rule.yaml") -> Path:
    path = rules_dir / name
    path.write_text(yaml.safe_dump(rule), encoding="utf-8")
    return path


# ── Loading and validation ────────────────────────────────────────────────────


def test_loads_single_rule(rules_dir: Path) -> None:
    write_rule(
        rules_dir,
        {
            "id": "MY-001",
            "title": "Test",
            "severity": "high",
            "match": {"type": "string", "patterns": ["needle"]},
        },
    )
    rules = load_rules(rules_dir)
    assert [r.rule_id for r in rules] == ["MY-001"]
    assert rules[0].severity is Severity.HIGH


def test_loads_list_of_rules(rules_dir: Path) -> None:
    write_rule(
        rules_dir,
        [
            {"id": "A", "match": {"patterns": ["a"]}},
            {"id": "B", "match": {"patterns": ["b"]}},
        ],
    )
    assert {r.rule_id for r in load_rules(rules_dir)} == {"A", "B"}


def test_missing_directory_returns_empty(tmp_path: Path) -> None:
    assert load_rules(tmp_path / "absent") == []


def test_supports_yml_extension(rules_dir: Path) -> None:
    write_rule(rules_dir, {"id": "Y", "match": {"patterns": ["x"]}}, name="r.yml")
    assert [r.rule_id for r in load_rules(rules_dir)] == ["Y"]


def test_severity_defaults_to_info(rules_dir: Path) -> None:
    write_rule(rules_dir, {"id": "D", "match": {"patterns": ["x"]}})
    assert load_rules(rules_dir)[0].severity is Severity.INFO


def test_accepts_critical_severity(rules_dir: Path) -> None:
    write_rule(
        rules_dir, {"id": "C", "severity": "critical", "match": {"patterns": ["x"]}}
    )
    assert load_rules(rules_dir)[0].severity is Severity.CRITICAL


@pytest.mark.parametrize(
    "bad_rule",
    [
        {"title": "no id", "match": {"patterns": ["x"]}},
        {"id": "", "match": {"patterns": ["x"]}},
        {"id": "S", "severity": "urgent", "match": {"patterns": ["x"]}},
        {"id": "T", "match": {"type": "nonsense", "patterns": ["x"]}},
        {"id": "G", "match": {"target": "nonsense", "patterns": ["x"]}},
        {"id": "P", "match": {"patterns": []}},
        {"id": "N", "match": "not-a-mapping"},
        {"id": "R", "match": {"type": "regex", "patterns": ["([unclosed"]}},
    ],
)
def test_invalid_rules_are_skipped(rules_dir: Path, bad_rule: dict) -> None:
    write_rule(rules_dir, bad_rule)
    assert load_rules(rules_dir) == []


def test_one_bad_rule_does_not_discard_the_good_ones(
    rules_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A single invalid severity used to abort the whole custom-rule pass."""
    write_rule(
        rules_dir,
        [
            {"id": "GOOD-1", "match": {"patterns": ["a"]}},
            {"id": "BAD", "severity": "not-a-severity", "match": {"patterns": ["b"]}},
            {"id": "GOOD-2", "match": {"patterns": ["c"]}},
        ],
    )
    with caplog.at_level(logging.WARNING):
        rules = load_rules(rules_dir)

    assert {r.rule_id for r in rules} == {"GOOD-1", "GOOD-2"}
    assert "BAD" not in {r.rule_id for r in rules}
    assert any("invalid severity" in m for m in caplog.messages)


def test_malformed_yaml_is_reported(
    rules_dir: Path, caplog: pytest.LogCaptureFixture
) -> None:
    (rules_dir / "broken.yaml").write_text("key: [unclosed", encoding="utf-8")
    with caplog.at_level(logging.WARNING):
        assert load_rules(rules_dir) == []
    assert any("Failed to read" in m for m in caplog.messages)


# ── Matching: binary target ───────────────────────────────────────────────────


def test_string_match_produces_finding(rules_dir: Path, make_ios_ctx) -> None:
    write_rule(
        rules_dir,
        {
            "id": "MY-001",
            "title": "Found needle",
            "severity": "high",
            "match": {"type": "string", "patterns": ["needle"]},
        },
    )
    ctx = make_ios_ctx(strings={"a needle in a haystack", "unrelated"})

    findings = apply_custom_rules(ctx, rules_dir=rules_dir)

    assert len(findings) == 1
    assert findings[0].rule_id == "MY-001"
    assert findings[0].severity is Severity.HIGH
    assert findings[0].extra == {"custom": True}
    assert "needle" in findings[0].evidence


def test_string_match_absent_produces_nothing(rules_dir: Path, make_ios_ctx) -> None:
    write_rule(rules_dir, {"id": "MY-001", "match": {"patterns": ["needle"]}})
    ctx = make_ios_ctx(strings={"nothing here"})
    assert apply_custom_rules(ctx, rules_dir=rules_dir) == []


def test_regex_match(rules_dir: Path, make_ios_ctx) -> None:
    write_rule(
        rules_dir,
        {
            "id": "RX-001",
            "match": {"type": "regex", "patterns": [r"v\d+\.\d+"]},
        },
    )
    ctx = make_ios_ctx(strings={"version v2.5 build"})
    assert len(apply_custom_rules(ctx, rules_dir=rules_dir)) == 1


def test_any_false_requires_all_patterns(rules_dir: Path, make_ios_ctx) -> None:
    write_rule(
        rules_dir,
        {
            "id": "ALL-001",
            "match": {"patterns": ["alpha", "beta"], "any": False},
        },
    )
    partial = make_ios_ctx(strings={"alpha only"})
    assert apply_custom_rules(partial, rules_dir=rules_dir) == []

    both = make_ios_ctx(strings={"alpha here", "beta there"})
    assert len(apply_custom_rules(both, rules_dir=rules_dir)) == 1


def test_any_true_needs_one_pattern(rules_dir: Path, make_ios_ctx) -> None:
    write_rule(rules_dir, {"id": "ANY-001", "match": {"patterns": ["alpha", "beta"]}})
    ctx = make_ios_ctx(strings={"alpha only"})
    assert len(apply_custom_rules(ctx, rules_dir=rules_dir)) == 1


# ── Matching: plist / manifest targets ────────────────────────────────────────


def test_plist_key_match(rules_dir: Path, make_ios_ctx) -> None:
    write_rule(
        rules_dir,
        {
            "id": "PL-001",
            "match": {
                "type": "plist_key",
                "target": "info_plist",
                "patterns": ["NSAppTransportSecurity.NSAllowsArbitraryLoads"],
            },
        },
    )
    ctx = make_ios_ctx(
        info_plist={"NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True}}
    )

    findings = apply_custom_rules(ctx, rules_dir=rules_dir)

    assert len(findings) == 1
    assert "NSAllowsArbitraryLoads" in findings[0].evidence


def test_plist_key_absent(rules_dir: Path, make_ios_ctx) -> None:
    write_rule(
        rules_dir,
        {
            "id": "PL-002",
            "match": {
                "type": "plist_key",
                "target": "info_plist",
                "patterns": ["Missing.Key"],
            },
        },
    )
    assert apply_custom_rules(make_ios_ctx(info_plist={}), rules_dir=rules_dir) == []


def test_android_manifest_target(rules_dir: Path, make_android_ctx) -> None:
    write_rule(
        rules_dir,
        {
            "id": "AND-CUSTOM-001",
            "match": {
                "type": "plist_key",
                "target": "android_manifest",
                "patterns": ["debuggable"],
            },
        },
    )
    ctx = make_android_ctx(manifest_summary={"debuggable": "true"})

    findings = apply_custom_rules(ctx, rules_dir=rules_dir)

    assert len(findings) == 1
    assert "debuggable" in findings[0].evidence


def test_android_binary_target_searches_dex_strings(
    rules_dir: Path, make_android_ctx
) -> None:
    """Android 'binary' rules must see DEX constants, not only .so strings."""
    write_rule(rules_dir, {"id": "AND-002", "match": {"patterns": ["SECRET_FLAG"]}})
    ctx = make_android_ctx(dex_strings={"SECRET_FLAG=1"})

    assert len(apply_custom_rules(ctx, rules_dir=rules_dir)) == 1


def test_no_rules_directory_yields_no_findings(make_ios_ctx, tmp_path: Path) -> None:
    ctx = make_ios_ctx(strings={"anything"})
    assert apply_custom_rules(ctx, rules_dir=tmp_path / "nope") == []
