"""SQLite-backed scan result storage with JSON migration support."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path

from shingan.core.models import ScanResult

DEFAULT_DB = Path.home() / ".shingan" / "shingan.db"
_LEGACY_SCANS_DIR = Path.home() / ".shingan" / "scans"


@contextmanager
def _connect(db_path: Path):
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


class ScanStore:
    def __init__(self, db_path: Path = DEFAULT_DB) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._migrate_json()

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
            """)

    def _migrate_json(self) -> None:
        """Import any JSON files from the legacy scans directory (runs once)."""
        if not _LEGACY_SCANS_DIR.exists():
            return
        for p in sorted(_LEGACY_SCANS_DIR.glob("*.json")):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                scan_id = data.get("scan_id")
                if not scan_id:
                    continue
                with _connect(self.db_path) as conn:
                    exists = conn.execute(
                        "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
                    ).fetchone()
                    if not exists:
                        conn.execute(
                            "INSERT INTO scans VALUES (?,?,?,?,?,?,?)",
                            (
                                scan_id,
                                data.get("app_id", ""),
                                data.get("app_version", ""),
                                data.get("build", ""),
                                data.get("ipa_name", ""),
                                data.get("scanned_at", ""),
                                json.dumps(data),
                            ),
                        )
            except Exception:
                continue

    # ── CRUD ─────────────────────────────────────────────────────────────────

    def save(self, result: ScanResult) -> None:
        with _connect(self.db_path) as conn:
            conn.execute(
                """INSERT OR REPLACE INTO scans VALUES (?,?,?,?,?,?,?)""",
                (
                    result.scan_id,
                    result.app_id,
                    result.app_version,
                    result.build,
                    result.ipa_name,
                    result.scanned_at,
                    json.dumps(result.to_dict(), ensure_ascii=False),
                ),
            )

    def load(self, scan_id: str) -> ScanResult:
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT data FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        if not row:
            raise FileNotFoundError(f"Scan not found: {scan_id}")
        return ScanResult.from_dict(json.loads(row["data"]))

    def list_scans(self, app_id: str | None = None) -> list[dict]:
        sql = "SELECT data FROM scans"
        params: tuple = ()
        if app_id:
            sql += " WHERE app_id = ?"
            params = (app_id,)
        sql += " ORDER BY scanned_at DESC"
        with _connect(self.db_path) as conn:
            rows = conn.execute(sql, params).fetchall()
        results = []
        for row in rows:
            try:
                d = json.loads(row["data"])
                results.append(
                    {
                        "scan_id": d.get("scan_id"),
                        "scanned_at": d.get("scanned_at"),
                        "app_id": d.get("app_id"),
                        "app_version": d.get("app_version"),
                        "build": d.get("build"),
                        "ipa_name": d.get("ipa_name"),
                        "summary": d.get("summary", {}),
                    }
                )
            except Exception:
                continue
        return results

    def latest_for_app(self, app_id: str) -> ScanResult | None:
        scans = self.list_scans(app_id=app_id)
        if not scans:
            return None
        return self.load(scans[0]["scan_id"])

    def delete(self, scan_id: str) -> None:
        with _connect(self.db_path) as conn:
            conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))

    # ── Baselines ────────────────────────────────────────────────────────────

    def set_baseline(self, app_id: str, scan_id: str) -> None:
        with _connect(self.db_path) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO baselines VALUES (?,?)", (app_id, scan_id)
            )

    def get_baseline(self, app_id: str) -> str | None:
        with _connect(self.db_path) as conn:
            row = conn.execute(
                "SELECT scan_id FROM baselines WHERE app_id = ?", (app_id,)
            ).fetchone()
        return row["scan_id"] if row else None
