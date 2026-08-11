"""Suppression / allowlist management.

Suppressions are stored in ~/.shingan/suppressions.json as a list of entries:
  { "rule_id": "IOS-SEC-002-entropy", "evidence_prefix": "abc123", "reason": "test fixture" }

A Finding is suppressed if its rule_id matches AND its evidence starts with
evidence_prefix.  Omitting evidence_prefix suppresses all findings for that
rule_id.
"""

from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

from shingan.core.models import Finding
from shingan.core.paths import default_suppressions_path

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
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
    def from_dict(cls, d: dict) -> Suppression:
        return cls(
            rule_id=d["rule_id"],
            evidence_prefix=d.get("evidence_prefix", ""),
            reason=d.get("reason", ""),
        )


class SuppressionStore:
    """Loads, mutates, and applies suppression entries."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path is not None else default_suppressions_path()
        self._suppressions: list[Suppression] = []
        self._load()

    def _load(self) -> None:
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            # Previously swallowed silently, so a corrupt file looked exactly
            # like "no suppressions configured".
            logger.warning(
                "Could not read suppressions from %s (%s) — treating as empty",
                self.path,
                exc,
            )
            return

        if not isinstance(raw, list):
            logger.warning(
                "Suppression file %s must contain a list — treating as empty", self.path
            )
            return

        loaded: list[Suppression] = []
        for entry in raw:
            try:
                loaded.append(Suppression.from_dict(entry))
            except (KeyError, TypeError, AttributeError) as exc:
                logger.warning(
                    "Skipping malformed suppression entry %r: %s", entry, exc
                )
        self._suppressions = loaded

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(
            [s.to_dict() for s in self._suppressions], indent=2, ensure_ascii=False
        )
        # Write via a temporary file so an interrupted write cannot truncate the
        # existing suppression list.
        tmp_path = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp_path.write_text(payload, encoding="utf-8")
        tmp_path.replace(self.path)

    def add(
        self, rule_id: str, evidence_prefix: str = "", reason: str = ""
    ) -> Suppression:
        """Add a suppression, or return the existing identical one unchanged."""
        sup = Suppression(
            rule_id=rule_id, evidence_prefix=evidence_prefix, reason=reason
        )
        existing = next(
            (
                s
                for s in self._suppressions
                if s.rule_id == rule_id and s.evidence_prefix == evidence_prefix
            ),
            None,
        )
        if existing is not None:
            return existing
        self._suppressions.append(sup)
        self._save()
        return sup

    def remove(self, rule_id: str, evidence_prefix: str = "") -> int:
        """Remove matching suppressions and return how many were removed."""
        remaining = [
            s
            for s in self._suppressions
            if not (s.rule_id == rule_id and s.evidence_prefix == evidence_prefix)
        ]
        removed = len(self._suppressions) - len(remaining)
        if removed:
            self._suppressions = remaining
            self._save()
        return removed

    def list_all(self) -> list[Suppression]:
        return list(self._suppressions)

    def apply(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        """Return (active_findings, suppressed_findings)."""
        # Index by rule_id so each finding only tests the suppressions that
        # could possibly apply to it.
        by_rule: dict[str, list[Suppression]] = defaultdict(list)
        for sup in self._suppressions:
            by_rule[sup.rule_id].append(sup)

        active: list[Finding] = []
        suppressed: list[Finding] = []
        for finding in findings:
            candidates = by_rule.get(finding.rule_id, ())
            if any(s.matches(finding) for s in candidates):
                suppressed.append(finding)
            else:
                active.append(finding)
        return active, suppressed
