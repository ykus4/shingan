"""Hardened archive extraction.

IPA and APK files are *untrusted input* — shingan analyses artifacts that may
well be adversarial, so extraction is worth doing deliberately.

What ``ZipFile.extractall()`` already handles: CPython's ``_extract_member``
strips ``..`` and leading-slash components from member names and writes symlink
entries as ordinary files, so plain path traversal ("Zip Slip") is *not*
exploitable through it. Extraction is contained in the destination directory.

What it does not handle, and what this module adds:

* **Zip bombs** — ``extractall`` will happily expand a few KiB into gigabytes.
  Total uncompressed size, overall compression ratio, and member count are
  budgeted here.
* **Silent path rewriting** — ``extractall`` quietly rewrites a hostile name
  like ``../evil`` to ``evil`` and carries on. Rejecting the archive instead
  surfaces a malformed or hostile artifact rather than analysing a mangled
  version of it.
* **Symlink members** — dropped explicitly rather than materialised as regular
  files containing a path, which is only ever noise for a static analyser.

The path containment check is therefore defence-in-depth, not a fix for a live
vulnerability; the size budgets are the substantive protection.
"""

from __future__ import annotations

import logging
import shutil
import zipfile
from pathlib import Path

from shingan.core.constants import (
    MAX_ARCHIVE_MEMBERS,
    MAX_COMPRESSION_RATIO,
    MAX_UNCOMPRESSED_BYTES,
)

logger = logging.getLogger(__name__)


class UnsafeArchiveError(ValueError):
    """Raised when an archive member would escape the destination or blow a budget."""


def _is_within(base: Path, target: Path) -> bool:
    """True if ``target`` resolves to a location inside ``base``."""
    try:
        target.relative_to(base)
    except ValueError:
        return False
    return True


def _validate_members(zf: zipfile.ZipFile, dest: Path) -> list[zipfile.ZipInfo]:
    """Return the members that are safe to extract, or raise."""
    infos = zf.infolist()

    if len(infos) > MAX_ARCHIVE_MEMBERS:
        raise UnsafeArchiveError(
            f"Archive has {len(infos)} members, exceeding the limit of "
            f"{MAX_ARCHIVE_MEMBERS}"
        )

    total_uncompressed = 0
    total_compressed = 0
    safe: list[zipfile.ZipInfo] = []

    for info in infos:
        name = info.filename

        # Reject absolute paths and drive-letter/UNC style names outright.
        if name.startswith(("/", "\\")) or ":" in name.split("/", 1)[0]:
            raise UnsafeArchiveError(f"Archive member has an absolute path: {name!r}")

        # Resolve the would-be destination and confirm it stays inside dest.
        target = (dest / name).resolve()
        if not _is_within(dest, target):
            raise UnsafeArchiveError(
                f"Archive member escapes the destination directory: {name!r}"
            )

        # Refuse symlinks: they can redirect later writes outside dest, and a
        # static analyser never needs to follow them.
        mode = info.external_attr >> 16
        if mode and (mode & 0o170000) == 0o120000:
            logger.debug("Skipping symlink in archive: %s", name)
            continue

        total_uncompressed += info.file_size
        total_compressed += info.compress_size
        if total_uncompressed > MAX_UNCOMPRESSED_BYTES:
            raise UnsafeArchiveError(
                f"Archive expands to more than {MAX_UNCOMPRESSED_BYTES} bytes "
                "— refusing to extract (possible zip bomb)"
            )

        safe.append(info)

    # A very high overall ratio is the other zip-bomb signature.
    if total_compressed > 0:
        ratio = total_uncompressed / total_compressed
        if ratio > MAX_COMPRESSION_RATIO:
            raise UnsafeArchiveError(
                f"Archive compression ratio {ratio:.0f}:1 exceeds the limit of "
                f"{MAX_COMPRESSION_RATIO}:1 (possible zip bomb)"
            )

    return safe


def safe_extract_zip(archive_path: Path, dest: Path) -> None:
    """Extract ``archive_path`` into ``dest``, rejecting unsafe members.

    Raises:
        UnsafeArchiveError: a member escapes ``dest`` or a size budget is hit.
        ValueError: the file is not a readable zip archive.
    """
    dest = dest.resolve()
    dest.mkdir(parents=True, exist_ok=True)

    try:
        with zipfile.ZipFile(archive_path, "r") as zf:
            members = _validate_members(zf, dest)
            for info in members:
                zf.extract(info, path=dest)
    except zipfile.BadZipFile as exc:
        raise ValueError(f"Not a valid zip archive: {archive_path}") from exc


def safe_filename(name: str, fallback: str = "upload.bin") -> str:
    """Reduce an untrusted filename to a single safe path component.

    Used for uploads, where the client controls the name and a value like
    ``../../etc/passwd`` must not be honoured.
    """
    candidate = Path(name.replace("\\", "/")).name.strip()
    if not candidate or candidate in {".", ".."}:
        return fallback
    return candidate


def remove_tree(path: Path) -> None:
    """Best-effort recursive delete used by bundle cleanup."""
    shutil.rmtree(path, ignore_errors=True)
