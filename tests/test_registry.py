"""Tests for checker discovery and execution."""

from __future__ import annotations

import logging

import pytest

from shingan.core.checkers.registry import (
    Checker,
    android_checkers,
    checkers_for,
    ios_checkers,
    run_checkers,
)
from shingan.core.models import Finding, Severity

# The checker set the analyzer wired up by hand before discovery existed.
EXPECTED_IOS = {
    "ats",
    "binary_protection",
    "crypto",
    "data_handling",
    "debug_flags",
    "keychain",
    "metadata",
    "protection",
    "sbom",
    "secrets",
    "symbols",
    "webview",
}

EXPECTED_ANDROID = {
    "binary_protection",
    "crypto",
    "data_handling",
    "debug_flags",
    "manifest",
    "network_security",
    "permissions",
    "protection",
    "sbom",
    "secrets",
    "signing",
    "webview",
}


def test_discovers_all_ios_checkers() -> None:
    assert {c.name for c in ios_checkers()} == EXPECTED_IOS


def test_discovers_all_android_checkers() -> None:
    assert {c.name for c in android_checkers()} == EXPECTED_ANDROID


def test_discovery_order_is_deterministic() -> None:
    names = [c.name for c in ios_checkers()]
    assert names == sorted(names)
    assert names == [c.name for c in ios_checkers()]


def test_checkers_for_platform() -> None:
    assert {c.name for c in checkers_for("ios")} == EXPECTED_IOS
    assert {c.name for c in checkers_for("android")} == EXPECTED_ANDROID


def test_checkers_for_unknown_platform() -> None:
    with pytest.raises(ValueError, match="Unknown platform"):
        checkers_for("windows-phone")


def test_every_checker_is_callable(make_ios_ctx) -> None:
    ctx = make_ios_ctx(strings=set())
    for checker in ios_checkers():
        assert callable(checker)
        assert isinstance(checker(ctx), list)


# ── run_checkers isolation ────────────────────────────────────────────────────


def _ok(_ctx: object) -> list[Finding]:
    return [Finding("OK-1", "ok", Severity.LOW, "")]


def _boom(_ctx: object) -> list[Finding]:
    raise RuntimeError("boom")


def test_run_checkers_aggregates_findings() -> None:
    checkers = [
        Checker("a", "tests.a", _ok),
        Checker("b", "tests.b", _ok),
    ]
    assert len(run_checkers(checkers, object())) == 2


def test_run_checkers_isolates_failures(caplog: pytest.LogCaptureFixture) -> None:
    checkers = [
        Checker("boom", "tests.boom", _boom),
        Checker("ok", "tests.ok", _ok),
    ]
    with caplog.at_level(logging.ERROR):
        findings = run_checkers(checkers, object())

    # The healthy checker still contributes.
    assert [f.rule_id for f in findings] == ["OK-1"]
    assert any("tests.boom" in m for m in caplog.messages)


def test_run_checkers_with_no_checkers() -> None:
    assert run_checkers([], object()) == []
