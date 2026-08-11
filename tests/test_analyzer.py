"""End-to-end tests for the analysis orchestrator."""

from __future__ import annotations

import datetime
import logging
from pathlib import Path

import pytest
import yaml

from shingan.core import analyzer
from shingan.core.analyzer import analyze
from shingan.core.models import Finding, Severity
from shingan.core.suppression import SuppressionStore


def test_analyze_ipa_populates_metadata(ipa_file: Path) -> None:
    result = analyze(ipa_file)

    assert result.platform == "ios"
    assert result.app_id == "com.example.app"
    assert result.app_version == "1.2.3"
    assert result.build == "42"
    assert result.artifact_name == "Example.ipa"
    assert result.scan_id
    assert result.scanned_at.endswith("Z")


def test_analyze_accepts_app_directory(app_bundle: Path) -> None:
    """.app is a directory; the CLI used to reject it before analysis started."""
    result = analyze(app_bundle)
    assert result.app_id == "com.example.app"


def test_scanned_at_is_timezone_aware_utc(ipa_file: Path) -> None:
    result = analyze(ipa_file)
    parsed = datetime.datetime.fromisoformat(result.scanned_at.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None
    # Sanity: within a day of now, i.e. genuinely current UTC.
    now = datetime.datetime.now(datetime.UTC)
    assert abs((now - parsed).total_seconds()) < 86_400


def test_analyze_runs_every_ios_checker(ipa_file: Path) -> None:
    """The registry should feed the analyzer all iOS checkers."""
    result = analyze(ipa_file)
    prefixes = {f.rule_id.split("-")[1] for f in result.findings}
    # A placeholder binary still triggers the plist and "missing protection"
    # checks, so several distinct rule families must appear.
    assert len(prefixes) >= 3


def test_analyze_missing_file() -> None:
    with pytest.raises(FileNotFoundError):
        analyze(Path("/nonexistent/App.ipa"))


def test_temp_dir_is_removed_after_analysis(ipa_file: Path, tmp_path: Path) -> None:
    before = set(tmp_path.parent.glob("shingan_*"))
    analyze(ipa_file)
    assert set(tmp_path.parent.glob("shingan_*")) == before


def test_explicit_work_dir_is_preserved(ipa_file: Path, tmp_path: Path) -> None:
    work_dir = tmp_path / "keep"
    analyze(ipa_file, work_dir=work_dir)
    assert work_dir.exists()


# ── Checker isolation ─────────────────────────────────────────────────────────


def test_a_failing_checker_does_not_abort_the_scan(
    ipa_file: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    from shingan.core.checkers.registry import Checker

    def exploding(_ctx: object) -> list[Finding]:
        raise RuntimeError("checker blew up")

    real = analyzer.checkers_for

    def patched(platform: str) -> list[Checker]:
        return [
            Checker(name="boom", module="tests.boom", run=exploding),
            *real(platform),
        ]

    monkeypatch.setattr(analyzer, "checkers_for", patched)

    with caplog.at_level(logging.ERROR):
        result = analyze(ipa_file)

    assert result.app_id == "com.example.app"
    assert any("tests.boom" in m for m in caplog.messages)


# ── Suppressions ──────────────────────────────────────────────────────────────


def test_suppressions_are_applied(ipa_file: Path, tmp_path: Path) -> None:
    baseline = analyze(ipa_file)
    assert baseline.findings, "expected the placeholder IPA to produce findings"
    target = baseline.findings[0].rule_id

    store = SuppressionStore(path=tmp_path / "sup.json")
    store.add(target)

    result = analyze(ipa_file, suppression_store=store)

    assert all(f.rule_id != target for f in result.findings)
    assert result.suppressed_count >= 1


# ── Custom rules on both platforms ────────────────────────────────────────────


def test_custom_rules_apply_to_ios(ipa_file: Path, tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "r.yaml").write_text(
        yaml.safe_dump(
            {
                "id": "CUSTOM-IOS-1",
                "title": "Placeholder marker",
                "severity": "low",
                "match": {"type": "string", "patterns": ["placeholder"]},
            }
        ),
        encoding="utf-8",
    )

    result = analyze(ipa_file, custom_rules_dir=rules_dir)

    assert any(f.rule_id == "CUSTOM-IOS-1" for f in result.findings)


def test_custom_rules_reach_the_android_path(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Android scans previously skipped apply_custom_rules() entirely."""
    calls: list[str] = []

    def fake_apply(ctx: object, rules_dir: Path | None = None) -> list[Finding]:
        calls.append(type(ctx).__name__)
        return [
            Finding(
                rule_id="CUSTOM-AND-1",
                title="custom",
                severity=Severity.LOW,
                description="",
            )
        ]

    monkeypatch.setattr(analyzer, "apply_custom_rules", fake_apply)
    monkeypatch.setattr(analyzer, "checkers_for", lambda _p: [])

    apk = tmp_path / "App.apk"
    apk.write_bytes(b"placeholder")

    from shingan.core.ingest import APKBundle

    bundle = APKBundle(
        apk_path=apk,
        work_dir=tmp_path,
        package_name="com.example.android",
        version_name="9.9",
        version_code="99",
    )
    monkeypatch.setattr(analyzer, "ingest", lambda *_a, **_k: bundle)

    result = analyze(apk)

    assert result.platform == "android"
    assert calls == ["AndroidCheckContext"]
    assert any(f.rule_id == "CUSTOM-AND-1" for f in result.findings)


def test_broken_custom_rules_do_not_abort_the_scan(
    ipa_file: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def exploding(*_a: object, **_k: object) -> list[Finding]:
        raise RuntimeError("rules exploded")

    monkeypatch.setattr(analyzer, "apply_custom_rules", exploding)

    with caplog.at_level(logging.ERROR):
        result = analyze(ipa_file)

    assert result.app_id == "com.example.app"
    assert any("Custom rules failed" in m for m in caplog.messages)


# ── Dynamic analysis ──────────────────────────────────────────────────────────


def test_dynamic_disabled_by_default(ipa_file: Path) -> None:
    result = analyze(ipa_file)
    assert not any(f.is_dynamic for f in result.findings)


def test_dynamic_failure_does_not_abort_the_scan(
    ipa_file: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    def exploding(**_k: object) -> list[Finding]:
        raise RuntimeError("device on fire")

    monkeypatch.setattr(
        "shingan.core.dynamic.run_dynamic_checks", exploding, raising=False
    )

    with caplog.at_level(logging.ERROR):
        result = analyze(ipa_file, dynamic=True)

    assert result.app_id == "com.example.app"
