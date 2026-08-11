"""Tests for artifact ingestion."""

from __future__ import annotations

import plistlib
import zipfile
from pathlib import Path

import pytest

from shingan.core.ingest import IPABundle, ingest
from tests.conftest import MINIMAL_PLIST

# ── Dispatch ──────────────────────────────────────────────────────────────────


def test_ingest_ipa(ipa_file: Path) -> None:
    bundle = ingest(ipa_file)
    try:
        assert isinstance(bundle, IPABundle)
        assert bundle.info_plist["CFBundleIdentifier"] == "com.example.app"
        assert bundle.binary_path.name == "Example"
        assert bundle.binary_path.exists()
    finally:
        bundle.cleanup()


def test_ingest_app_directory(app_bundle: Path) -> None:
    bundle = ingest(app_bundle)
    assert isinstance(bundle, IPABundle)
    assert bundle.app_dir == app_bundle
    # A .app is used in place; nothing was extracted, so nothing is owned.
    assert bundle.owned is False


def test_ingest_directory_containing_app(app_bundle: Path) -> None:
    bundle = ingest(app_bundle.parent)
    assert bundle.app_dir == app_bundle


def test_ingest_xcarchive(tmp_path: Path) -> None:
    archive = tmp_path / "Example.xcarchive"
    apps = archive / "Products" / "Applications" / "Example.app"
    apps.mkdir(parents=True)
    (apps / "Info.plist").write_bytes(plistlib.dumps(MINIMAL_PLIST))
    (apps / "Example").write_bytes(b"binary")

    bundle = ingest(archive)
    assert bundle.app_dir == apps


def test_ingest_missing_path(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Input not found"):
        ingest(tmp_path / "absent.ipa")


def test_ingest_unsupported_suffix(tmp_path: Path) -> None:
    other = tmp_path / "thing.txt"
    other.write_text("hello")
    with pytest.raises(ValueError, match="Unsupported input"):
        ingest(other)


def test_ingest_empty_directory(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    with pytest.raises(ValueError, match="Unsupported input"):
        ingest(empty)


# ── Malformed IPA handling ────────────────────────────────────────────────────


def test_ipa_without_payload(tmp_path: Path) -> None:
    ipa = tmp_path / "bad.ipa"
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("NotPayload/whatever.txt", "x")

    with pytest.raises(ValueError, match="no Payload directory"):
        ingest(ipa)


def test_ipa_payload_without_app(tmp_path: Path) -> None:
    ipa = tmp_path / "bad.ipa"
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("Payload/readme.txt", "x")

    with pytest.raises(ValueError, match=r"no \.app bundle"):
        ingest(ipa)


def test_ipa_that_is_not_a_zip(tmp_path: Path) -> None:
    ipa = tmp_path / "bad.ipa"
    ipa.write_text("not a zip")
    with pytest.raises(ValueError, match="Not a valid zip archive"):
        ingest(ipa)


def test_app_without_info_plist(tmp_path: Path) -> None:
    app = tmp_path / "Bare.app"
    app.mkdir()
    with pytest.raises(ValueError, match=r"Info\.plist not found"):
        ingest(app)


def test_app_without_bundle_executable(tmp_path: Path) -> None:
    app = tmp_path / "NoExec.app"
    app.mkdir()
    (app / "Info.plist").write_bytes(plistlib.dumps({"CFBundleIdentifier": "x"}))
    with pytest.raises(ValueError, match="missing CFBundleExecutable"):
        ingest(app)


def test_app_with_missing_binary(tmp_path: Path) -> None:
    app = tmp_path / "Ghost.app"
    app.mkdir()
    (app / "Info.plist").write_bytes(plistlib.dumps(MINIMAL_PLIST))
    with pytest.raises(ValueError, match="Binary not found"):
        ingest(app)


def test_cfbundleexecutable_cannot_escape_the_bundle(tmp_path: Path) -> None:
    """CFBundleExecutable comes from the untrusted artifact."""
    app = tmp_path / "Escape.app"
    app.mkdir()
    (tmp_path / "outside").write_bytes(b"payload")
    plist = dict(MINIMAL_PLIST, CFBundleExecutable="../outside")
    (app / "Info.plist").write_bytes(plistlib.dumps(plist))

    with pytest.raises(ValueError, match="escapes the app bundle"):
        ingest(app)


# ── Cleanup semantics ─────────────────────────────────────────────────────────


def test_extracted_ipa_is_cleaned_up(ipa_file: Path) -> None:
    bundle = ingest(ipa_file)
    work_dir = bundle.work_dir
    assert bundle.owned is True
    assert work_dir.exists()

    bundle.cleanup()

    assert not work_dir.exists()


def test_cleanup_leaves_caller_supplied_work_dir(
    ipa_file: Path, tmp_path: Path
) -> None:
    work_dir = tmp_path / "explicit"
    bundle = ingest(ipa_file, work_dir=work_dir)

    bundle.cleanup()

    # The caller owns a directory it supplied, so it must survive.
    assert work_dir.exists()


def test_bundle_works_as_context_manager(ipa_file: Path) -> None:
    with ingest(ipa_file) as bundle:
        work_dir = bundle.work_dir
        assert work_dir.exists()
    assert not work_dir.exists()


def test_failed_extraction_does_not_leak_temp_dir(tmp_path: Path) -> None:
    ipa = tmp_path / "bad.ipa"
    with zipfile.ZipFile(ipa, "w") as zf:
        zf.writestr("NotPayload/x.txt", "x")

    before = set(Path(tmp_path).parent.glob("shingan_*"))
    with pytest.raises(ValueError):
        ingest(ipa)
    after = set(Path(tmp_path).parent.glob("shingan_*"))

    assert before == after
