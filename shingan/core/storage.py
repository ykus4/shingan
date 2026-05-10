"""JSON-based scan result storage."""

from __future__ import annotations

import json
from pathlib import Path

from shingan.core.models import ScanResult

DEFAULT_STORE = Path.home() / ".shingan" / "scans"


class ScanStore:
    def __init__(self, directory: Path = DEFAULT_STORE) -> None:
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)

    def save(self, result: ScanResult) -> Path:
        path = self.directory / f"{result.scan_id}.json"
        path.write_text(
            json.dumps(result.to_dict(), ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return path

    def load(self, scan_id: str) -> ScanResult:
        path = self.directory / f"{scan_id}.json"
        if not path.exists():
            raise FileNotFoundError(f"Scan not found: {scan_id}")
        data = json.loads(path.read_text(encoding="utf-8"))
        return ScanResult.from_dict(data)

    def list_scans(self, app_id: str | None = None) -> list[dict]:
        results = []
        for p in sorted(
            self.directory.glob("*.json"), key=lambda x: x.stat().st_mtime, reverse=True
        ):
            try:
                data = json.loads(p.read_text(encoding="utf-8"))
                if app_id and data.get("app_id") != app_id:
                    continue
                results.append(
                    {
                        "scan_id": data.get("scan_id"),
                        "scanned_at": data.get("scanned_at"),
                        "app_id": data.get("app_id"),
                        "app_version": data.get("app_version"),
                        "build": data.get("build"),
                        "ipa_name": data.get("ipa_name"),
                        "summary": data.get("summary", {}),
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
        path = self.directory / f"{scan_id}.json"
        if path.exists():
            path.unlink()
