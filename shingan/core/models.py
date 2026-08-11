"""Shared data models for shingan findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from shingan.core.constants import FINGERPRINT_EVIDENCE_LEN


class Severity(StrEnum):
    """Finding severity, ordered most to least urgent."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Sort key: 0 is most severe. Use instead of ad-hoc order tables."""
        return _SEVERITY_RANK[self]

    @property
    def color(self) -> str:
        """Rich markup colour used by the terminal renderer."""
        return _SEVERITY_COLOR[self]

    def at_least(self, threshold: Severity) -> bool:
        """True when this severity is as severe as ``threshold`` or worse."""
        return self.rank <= threshold.rank


# Declared after the enum body so the members exist; keyed by member, not by
# string, so a typo is an immediate KeyError rather than a silent miss.
_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_SEVERITY_COLOR: dict[Severity, str] = {
    Severity.CRITICAL: "bright_red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "green",
    Severity.INFO: "cyan",
}

#: Severities in report order, most severe first.
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    description: str
    evidence: str = ""  # snippet / detail shown in report
    recommendation: str = ""
    masvs: str = ""  # e.g. "MASVS-RESILIENCE-1"
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def is_dynamic(self) -> bool:
        """True for findings produced by dynamic (on-device) analysis."""
        return self.extra.get("source") == "dynamic"

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "masvs": self.masvs,
            "extra": self.extra,
        }

    @classmethod
    def from_dict(cls, d: dict) -> Finding:
        return cls(
            rule_id=d["rule_id"],
            title=d["title"],
            severity=Severity(d["severity"]),
            description=d["description"],
            evidence=d.get("evidence", ""),
            recommendation=d.get("recommendation", ""),
            masvs=d.get("masvs", ""),
            extra=d.get("extra", {}),
        )

    def fingerprint(self) -> str:
        """Stable identifier for diff comparison."""
        return f"{self.rule_id}:{self.evidence[:FINGERPRINT_EVIDENCE_LEN]}"


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    """Count findings per severity in a single pass."""
    counts = {severity.value: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        counts[finding.severity.value] += 1
    return counts


@dataclass
class ScanResult:
    app_id: str  # CFBundleIdentifier / package name
    app_version: str  # CFBundleShortVersionString / versionName
    build: str  # CFBundleVersion / versionCode
    artifact_name: str  # artifact filename (IPA or APK)
    findings: list[Finding] = field(default_factory=list)
    scan_id: str = ""
    scanned_at: str = ""
    suppressed_count: int = 0
    platform: str = "ios"  # "ios" | "android"

    @property
    def ipa_name(self) -> str:
        """Deprecated alias for :attr:`artifact_name`.

        Retained because the field is named ``ipa_name`` in persisted JSON and
        in the public API, which predates Android support.
        """
        return self.artifact_name

    def to_dict(self) -> dict:
        static = [f for f in self.findings if not f.is_dynamic]
        dynamic = [f for f in self.findings if f.is_dynamic]

        static_counts = severity_counts(static)
        dynamic_counts = severity_counts(dynamic)
        totals = {
            severity.value: static_counts[severity.value]
            + dynamic_counts[severity.value]
            for severity in SEVERITY_ORDER
        }

        return {
            "scan_id": self.scan_id,
            "scanned_at": self.scanned_at,
            "app_id": self.app_id,
            "app_version": self.app_version,
            "build": self.build,
            # Kept as "ipa_name" for backward compatibility with existing
            # consumers; "artifact_name" is the preferred spelling.
            "ipa_name": self.artifact_name,
            "artifact_name": self.artifact_name,
            "platform": self.platform,
            "summary": {
                # Top-level totals (backward compatible)
                **totals,
                "total": len(self.findings),
                "suppressed": self.suppressed_count,
                # Source breakdown (v1.2+)
                "static": {**static_counts, "total": len(static)},
                "dynamic": {
                    **dynamic_counts,
                    "total": len(dynamic),
                    "bypassed": sum(
                        1 for f in dynamic if f.extra.get("outcome") == "bypassed"
                    ),
                    "resistant": sum(
                        1 for f in dynamic if f.extra.get("outcome") == "resistant"
                    ),
                },
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, d: dict) -> ScanResult:
        result = cls(
            scan_id=d.get("scan_id", ""),
            scanned_at=d.get("scanned_at", ""),
            app_id=d["app_id"],
            app_version=d["app_version"],
            build=d["build"],
            artifact_name=d.get("artifact_name") or d["ipa_name"],
            suppressed_count=d.get("summary", {}).get("suppressed", 0),
            platform=d.get("platform", "ios"),
        )
        result.findings = [Finding.from_dict(f) for f in d.get("findings", [])]
        return result
