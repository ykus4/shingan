"""Shared data models for shingan findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from shingan.core.constants import FINGERPRINT_EVIDENCE_LEN


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


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
    def from_dict(cls, d: dict) -> "Finding":
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


@dataclass
class ScanResult:
    app_id: str  # CFBundleIdentifier / package name
    app_version: str  # CFBundleShortVersionString / versionName
    build: str  # CFBundleVersion / versionCode
    ipa_name: str  # artifact filename (IPA or APK)
    findings: list[Finding] = field(default_factory=list)
    scan_id: str = ""
    scanned_at: str = ""
    suppressed_count: int = 0
    platform: str = "ios"  # "ios" | "android"

    def to_dict(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "scanned_at": self.scanned_at,
            "app_id": self.app_id,
            "app_version": self.app_version,
            "build": self.build,
            "ipa_name": self.ipa_name,
            "platform": self.platform,
            "summary": {
                "high": sum(1 for f in self.findings if f.severity == Severity.HIGH),
                "medium": sum(
                    1 for f in self.findings if f.severity == Severity.MEDIUM
                ),
                "low": sum(1 for f in self.findings if f.severity == Severity.LOW),
                "info": sum(1 for f in self.findings if f.severity == Severity.INFO),
                "total": len(self.findings),
                "suppressed": self.suppressed_count,
            },
            "findings": [f.to_dict() for f in self.findings],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScanResult":
        result = cls(
            scan_id=d.get("scan_id", ""),
            scanned_at=d.get("scanned_at", ""),
            app_id=d["app_id"],
            app_version=d["app_version"],
            build=d["build"],
            ipa_name=d["ipa_name"],
            suppressed_count=d.get("summary", {}).get("suppressed", 0),
            platform=d.get("platform", "ios"),
        )
        result.findings = [Finding.from_dict(f) for f in d.get("findings", [])]
        return result
