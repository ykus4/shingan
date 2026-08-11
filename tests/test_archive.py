"""Tests for hardened archive extraction.

Note on scope: CPython's ``zipfile`` already contains extraction to the target
directory, so these traversal tests assert that shingan *rejects* a hostile
archive outright rather than silently extracting a rewritten version of it.
The size/ratio/member budgets are the substantive protection, since
``extractall`` has none.
"""

from __future__ import annotations

import zipfile
from pathlib import Path

import pytest

from shingan.core.archive import (
    UnsafeArchiveError,
    safe_extract_zip,
    safe_filename,
)


def _write_zip(path: Path, entries: dict[str, str]) -> Path:
    with zipfile.ZipFile(path, "w") as zf:
        for name, content in entries.items():
            zf.writestr(name, content)
    return path


# ── Zip Slip ──────────────────────────────────────────────────────────────────


def test_rejects_parent_traversal(tmp_path: Path) -> None:
    archive = _write_zip(tmp_path / "evil.zip", {"../escaped.txt": "pwned"})
    dest = tmp_path / "dest"

    with pytest.raises(UnsafeArchiveError, match="escapes the destination"):
        safe_extract_zip(archive, dest)

    assert not (tmp_path / "escaped.txt").exists()


def test_rejects_deep_parent_traversal(tmp_path: Path) -> None:
    archive = _write_zip(tmp_path / "evil.zip", {"a/b/../../../escaped.txt": "pwned"})
    dest = tmp_path / "dest"

    with pytest.raises(UnsafeArchiveError, match="escapes the destination"):
        safe_extract_zip(archive, dest)

    assert not (tmp_path / "escaped.txt").exists()


def test_rejects_absolute_path(tmp_path: Path) -> None:
    archive = _write_zip(tmp_path / "evil.zip", {"/tmp/absolute.txt": "pwned"})
    dest = tmp_path / "dest"

    with pytest.raises(UnsafeArchiveError, match="absolute path"):
        safe_extract_zip(archive, dest)


def test_extracts_benign_archive(tmp_path: Path) -> None:
    archive = _write_zip(
        tmp_path / "ok.zip",
        {"Payload/App.app/Info.plist": "plist", "Payload/App.app/App": "binary"},
    )
    dest = tmp_path / "dest"

    safe_extract_zip(archive, dest)

    assert (dest / "Payload/App.app/Info.plist").read_text() == "plist"
    assert (dest / "Payload/App.app/App").read_text() == "binary"


def test_nested_paths_inside_dest_are_allowed(tmp_path: Path) -> None:
    """A '..' that stays within dest is legitimate and must not be rejected."""
    archive = _write_zip(tmp_path / "ok.zip", {"a/b/../c.txt": "fine"})
    dest = tmp_path / "dest"

    safe_extract_zip(archive, dest)

    # Validation resolves the name to a/c.txt (inside dest, so accepted), while
    # zipfile's own member sanitisation drops the ".." and writes a/b/c.txt.
    assert (dest / "a/b/c.txt").read_text() == "fine"


def test_symlink_members_are_skipped(tmp_path: Path) -> None:
    archive_path = tmp_path / "link.zip"
    with zipfile.ZipFile(archive_path, "w") as zf:
        info = zipfile.ZipInfo("evil-link")
        # 0o120000 marks a symlink in the high bits of external_attr.
        info.external_attr = (0o120777 & 0xFFFF) << 16
        zf.writestr(info, "/etc/passwd")
        zf.writestr("real.txt", "content")

    dest = tmp_path / "dest"
    safe_extract_zip(archive_path, dest)

    assert (dest / "real.txt").read_text() == "content"
    assert not (dest / "evil-link").exists()


# ── Zip bombs ─────────────────────────────────────────────────────────────────


def test_rejects_high_compression_ratio(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("shingan.core.archive.MAX_COMPRESSION_RATIO", 10)
    archive_path = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive_path, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.bin", "0" * 2_000_000)

    with pytest.raises(UnsafeArchiveError, match="compression ratio"):
        safe_extract_zip(archive_path, tmp_path / "dest")


def test_rejects_oversized_expansion(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("shingan.core.archive.MAX_UNCOMPRESSED_BYTES", 100)
    archive = _write_zip(tmp_path / "big.zip", {"a.bin": "x" * 500})

    with pytest.raises(UnsafeArchiveError, match="expands to more than"):
        safe_extract_zip(archive, tmp_path / "dest")


def test_rejects_too_many_members(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr("shingan.core.archive.MAX_ARCHIVE_MEMBERS", 3)
    archive = _write_zip(tmp_path / "many.zip", {f"f{i}.txt": "x" for i in range(5)})

    with pytest.raises(UnsafeArchiveError, match="exceeding the limit"):
        safe_extract_zip(archive, tmp_path / "dest")


def test_rejects_non_zip(tmp_path: Path) -> None:
    not_zip = tmp_path / "plain.ipa"
    not_zip.write_text("definitely not a zip")

    with pytest.raises(ValueError, match="Not a valid zip archive"):
        safe_extract_zip(not_zip, tmp_path / "dest")


# ── Upload filename sanitisation ──────────────────────────────────────────────


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("App.ipa", "App.ipa"),
        ("../../etc/passwd", "passwd"),
        ("/absolute/path/App.apk", "App.apk"),
        ("dir\\windows\\App.ipa", "App.ipa"),
        ("", "fallback.ipa"),
        ("..", "fallback.ipa"),
        (".", "fallback.ipa"),
    ],
)
def test_safe_filename(raw: str, expected: str) -> None:
    assert safe_filename(raw, fallback="fallback.ipa") == expected
