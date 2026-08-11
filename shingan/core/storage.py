"""SQLite-backed scan result storage with JSON migration support."""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from shingan.core.constants import SCAN_LIST_LIMIT, SCHEMA_VERSION
from shingan.core.models import ScanResult
from shingan.core.paths import default_db_path, legacy_scans_dir

logger = logging.getLogger(__name__)

_SCAN_COLUMNS = (
    "scan_id",
    "app_id",
    "app_version",
    "build",
    "ipa_name",
    "scanned_at",
    "data",
)

# Built from the _SCAN_COLUMNS constant above, never from caller input; every
# value is still bound through a placeholder.
_INSERT_SCAN = (
    f"INSERT OR REPLACE INTO scans ({', '.join(_SCAN_COLUMNS)}) "  # noqa: S608
    f"VALUES ({', '.join('?' * len(_SCAN_COLUMNS))})"
)


@contextmanager
def _connect(db_path: Path) -> Iterator[sqlite3.Connection]:
    """Yield a connection, committing on success and rolling back on error."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


class ScanStore:
    """Persistent store for scan results and per-app baselines."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.db_path = Path(db_path) if db_path is not None else default_db_path()
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._migrate_json()

    # ── Schema ───────────────────────────────────────────────────────────────

    def _init_db(self) -> None:
        with _connect(self.db_path) as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id     TEXT PRIMARY KEY,
                    app_id      TEXT NOT NULL,
                    app_version TEXT NOT NULL,
                    build       TEXT NOT NULL,
                    ipa_name    TEXT NOT NULL,
                    scanned_at  TEXT NOT NULL,
                    data        TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_scans_app_id ON scans(app_id);
                CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at DESC);

                CREATE TABLE IF NOT EXISTS baselines (
                    app_id  TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS schema_meta (
                    key   TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
            """)
            conn.execute(
                "INSERT OR REPLACE INTO schema_meta (key, value) VALUES ('version', ?)",
                (str(SCHEMA_VERSION),),
            )

    def schema_version(self) -> int:
        """Version recorded in the database, for future migrations."""
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT value FROM schema_meta WHERE key = 'version'"
            ).fetchone()
        return int(row["value"]) if row else 0

    def _migrate_json(self) -> None:
        """Import scans from the pre-SQLite JSON directory.

        Runs at most once: the legacy directory is renamed with a ``.migrated``
        suffix afterwards, so subsequent constructions do not re-scan it.  The
        previous implementation re-globbed the directory on every instantiation.
        """
        legacy_dir = legacy_scans_dir()
        if not legacy_dir.is_dir():
            return

        imported = 0
        for path in sorted(legacy_dir.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                logger.warning("Skipping unreadable legacy scan %s: %s", path, exc)
                continue

            scan_id = data.get("scan_id")
            if not scan_id:
                logger.warning("Skipping legacy scan without scan_id: %s", path)
                continue

            try:
                with _connect(self.db_path) as conn:
                    exists = conn.execute(
                        "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
                    ).fetchone()
                    if exists:
                        continue
                    conn.execute(
                        _INSERT_SCAN,
                        (
                            scan_id,
                            data.get("app_id", ""),
                            data.get("app_version", ""),
                            data.get("build", ""),
                            data.get("ipa_name", ""),
                            data.get("scanned_at", ""),
                            json.dumps(data, ensure_ascii=False),
                        ),
                    )
                imported += 1
            except sqlite3.Error as exc:
                logger.warning("Failed to import legacy scan %s: %s", path, exc)

        try:
            legacy_dir.rename(legacy_dir.with_suffix(".migrated"))
        except OSError as exc:
            logger.debug("Could not rename legacy scans directory: %s", exc)

        if imported:
            logger.info("Imported %d legacy scan(s) from %s", imported, legacy_dir)

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def save(self, result: ScanResult) -> Path:
        """Persist a scan result and return the database path it was written to."""
        with _connect(self.db_path) as conn:
            conn.execute(
                _INSERT_SCAN,
                (
                    result.scan_id,
                    result.app_id,
                    result.app_version,
                    result.build,
                    result.artifact_name,
                    result.scanned_at,
                    json.dumps(result.to_dict(), ensure_ascii=False),
                ),
            )
        return self.db_path

    def load(self, scan_id: str) -> ScanResult:
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT data FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        if not row:
            raise FileNotFoundError(f"Scan not found: {scan_id}")
        return ScanResult.from_dict(json.loads(row["data"]))

    def list_scans(
        self, app_id: str | None = None, limit: int = SCAN_LIST_LIMIT
    ) -> list[dict]:
        """Return scan summaries, newest first.

        Reads the indexed columns and only the ``summary`` slice of the stored
        JSON, instead of deserialising every finding of every scan.
        """
        sql = (
            "SELECT scan_id, app_id, app_version, build, ipa_name, scanned_at, "
            "json_extract(data, '$.summary') AS summary FROM scans"
        )
        params: list[object] = []
        if app_id:
            sql += " WHERE app_id = ?"
            params.append(app_id)
        sql += " ORDER BY scanned_at DESC LIMIT ?"
        params.append(limit)

        with _connect(self.db_path) as conn:
            rows = conn.execute(sql, tuple(params)).fetchall()

        results: list[dict] = []
        for row in rows:
            try:
                summary = json.loads(row["summary"]) if row["summary"] else {}
            except json.JSONDecodeError:
                summary = {}
            results.append(
                {
                    "scan_id": row["scan_id"],
                    "scanned_at": row["scanned_at"],
                    "app_id": row["app_id"],
                    "app_version": row["app_version"],
                    "build": row["build"],
                    "ipa_name": row["ipa_name"],
                    "artifact_name": row["ipa_name"],
                    "summary": summary,
                }
            )
        return results

    def latest_for_app(self, app_id: str) -> ScanResult | None:
        """Most recent scan for an app, or None when it has never been scanned."""
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT scan_id FROM scans WHERE app_id = ? "
                "ORDER BY scanned_at DESC LIMIT 1",
                (app_id,),
            ).fetchone()
        return self.load(row["scan_id"]) if row else None

    def exists(self, scan_id: str) -> bool:
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return row is not None

    def delete(self, scan_id: str) -> bool:
        """Delete a scan and any baseline pointing at it.

        Returns True when a row was removed, so callers can report 404 instead
        of silently succeeding on an unknown ID.
        """
        with _connect(self.db_path) as conn:
            cursor = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM baselines WHERE scan_id = ?", (scan_id,))
        return cursor.rowcount > 0

    # ── Baselines ────────────────────────────────────────────────────────────

    def set_baseline(self, app_id: str, scan_id: str) -> None:
        with _connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO baselines (app_id, scan_id) VALUES (?, ?)",
                (app_id, scan_id),
            )

    def get_baseline(self, app_id: str) -> str | None:
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT scan_id FROM baselines WHERE app_id = ?", (app_id,)
            ).fetchone()
        return row["scan_id"] if row else None
