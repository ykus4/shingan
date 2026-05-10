"""Suppression / allowlist management.

Suppressions are stored in ~/.shingan/suppressions.json as a list of entries:
  { "rule_id": "IOS-SEC-002-entropy", "evidence_prefix": "abc123", "reason": "test fixture" }

A Finding is suppressed if its rule_id matches AND its evidence starts with evidence_prefix.
Omitting evidence_prefix suppresses all findings for that rule_id.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from shingan.core.models import Finding

DEFAULT_PATH = Path.home() / ".shingan" / "suppressions.json"


@dataclass
class Suppression:
    rule_id: str
    evidence_prefix: str = ""
    reason: str = ""

    def matches(self, finding: Finding) -> bool:
        if self.rule_id != finding.rule_id:
            return False
        if self.evidence_prefix:
            return finding.evidence.startswith(self.evidence_prefix)
        return True

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "evidence_prefix": self.evidence_prefix,
            "reason": self.reason,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Suppression":
        return cls(
            rule_id=d["rule_id"],
            evidence_prefix=d.get("evidence_prefix", ""),
            reason=d.get("reason", ""),
        )


class SuppressionStore:
    def __init__(self, path: Path = DEFAULT_PATH) -> None:
        self.path = Path(path)
        self._suppressions: list[Suppression] = []
        self._load()

    def _load(self) -> None:
        if self.path.exists():
            try:
                data = json.loads(self.path.read_text(encoding="utf-8"))
                self._suppressions = [Suppression.from_dict(d) for d in data]
            except Exception:
                self._suppressions = []

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_text(
            json.dumps([s.to_dict() for s in self._suppressions], indent=2),
            encoding="utf-8",
        )

    def add(
        self, rule_id: str, evidence_prefix: str = "", reason: str = ""
    ) -> Suppression:
        sup = Suppression(
            rule_id=rule_id, evidence_prefix=evidence_prefix, reason=reason
        )
        self._suppressions.append(sup)
        self._save()
        return sup

    def remove(self, rule_id: str, evidence_prefix: str = "") -> int:
        before = len(self._suppressions)
        self._suppressions = [
            s
            for s in self._suppressions
            if not (s.rule_id == rule_id and s.evidence_prefix == evidence_prefix)
        ]
        self._save()
        return before - len(self._suppressions)

    def list_all(self) -> list[Suppression]:
        return list(self._suppressions)

    def apply(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        """Return (active_findings, suppressed_findings)."""
        active, suppressed = [], []
        for f in findings:
            if any(s.matches(f) for s in self._suppressions):
                suppressed.append(f)
            else:
                active.append(f)
        return active, suppressed
