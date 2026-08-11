"""Tests for the check contexts (caching and corpus derivation)."""

from __future__ import annotations

from pathlib import Path

from shingan.core.constants import SECRETS_STRINGS_MIN_LEN
from shingan.core.context import AndroidCheckContext, CheckContext


def test_strings_is_empty_when_binary_is_missing() -> None:
    ctx = CheckContext(binary_path=Path("/nonexistent-binary"), info_plist={})
    assert ctx.strings == set()
    assert ctx.symbol_names == set()
    assert ctx.objc_classes == []
    assert ctx.all_text == set()


def test_strings_is_extracted_only_once(monkeypatch) -> None:
    calls: list[int] = []

    def counting(_path: Path, min_len: int) -> set[str]:
        calls.append(min_len)
        return {"alpha", "beta"}

    monkeypatch.setattr("shingan.core.context.extract_strings", counting)
    ctx = CheckContext(binary_path=Path("/x"), info_plist={})

    _ = ctx.strings
    _ = ctx.strings
    _ = ctx.long_strings

    # One subprocess for the whole context, not one per consumer.
    assert len(calls) == 1


def test_long_strings_filters_the_shared_corpus(make_ios_ctx) -> None:
    short = "a" * (SECRETS_STRINGS_MIN_LEN - 1)
    exact = "b" * SECRETS_STRINGS_MIN_LEN
    long = "c" * (SECRETS_STRINGS_MIN_LEN + 5)
    ctx = make_ios_ctx(strings={short, exact, long})

    assert ctx.long_strings == {exact, long}


def test_all_text_unions_strings_and_symbols(make_ios_ctx) -> None:
    ctx = make_ios_ctx(strings={"a"}, symbol_names={"b"})
    assert ctx.all_text == {"a", "b"}


def test_platform_markers() -> None:
    assert CheckContext(Path("/x"), {}).platform == "ios"
    assert AndroidCheckContext(Path("/x.apk")).platform == "android"


# ── Android context ───────────────────────────────────────────────────────────


def test_android_reuses_preparsed_apk() -> None:
    """Ingestion already parses the APK; the context must not parse it again."""
    sentinel = object()
    ctx = AndroidCheckContext(apk_path=Path("/x.apk"), apk=sentinel)
    assert ctx.apk is sentinel


def test_android_parses_lazily_when_not_supplied() -> None:
    ctx = AndroidCheckContext(apk_path=Path("/nonexistent.apk"))
    # androguard cannot parse a missing file, so this degrades to None
    # rather than raising.
    assert ctx.apk is None


def test_android_work_dir_defaults_to_apk_parent() -> None:
    ctx = AndroidCheckContext(apk_path=Path("/tmp/some/App.apk"))
    assert ctx.work_dir == Path("/tmp/some")


def test_android_long_strings_spans_dex_and_native(make_android_ctx) -> None:
    dex = "d" * (SECRETS_STRINGS_MIN_LEN + 1)
    native = "n" * (SECRETS_STRINGS_MIN_LEN + 1)
    tiny = "t"
    ctx = make_android_ctx(dex_strings={dex, tiny}, native_strings={native})

    assert ctx.long_strings == {dex, native}


def test_android_manifest_summary_without_apk() -> None:
    ctx = AndroidCheckContext(apk_path=Path("/nonexistent.apk"))
    assert ctx.manifest_summary == {}


def test_android_manifest_summary_is_cached() -> None:
    class FakeAPK:
        def __init__(self) -> None:
            self.calls = 0

        def get_package(self) -> str:
            self.calls += 1
            return "com.example"

        def get_androidversion_name(self) -> str:
            return "1.0"

        def get_androidversion_code(self) -> int:
            return 1

        def get_min_sdk_version(self) -> int:
            return 21

        def get_target_sdk_version(self) -> int:
            return 34

        def get_attribute_value(self, _tag: str, _attr: str) -> str:
            return "false"

        def get_permissions(self) -> list[str]:
            return ["android.permission.INTERNET"]

    apk = FakeAPK()
    ctx = AndroidCheckContext(apk_path=Path("/x.apk"), apk=apk)

    first = ctx.manifest_summary
    second = ctx.manifest_summary

    assert first is second
    # Rebuilt once, not once per rule that targets the manifest.
    assert apk.calls == 1
    assert first["package"] == "com.example"
    assert first["permissions"] == "android.permission.INTERNET"
