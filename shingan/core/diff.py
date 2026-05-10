"""Diff / baseline comparison between two ScanResults."""

from __future__ import annotations

from dataclasses import dataclass

from shingan.core.models import Finding, ScanResult, Status


@dataclass
class DiffResult:
    new: list[Finding]        # appeared in current, not in baseline
    fixed: list[Finding]      # were in baseline, gone in current
    persisted: list[Finding]  # in both baseline and current

    @property
    def new_fingerprints(self) -> set[str]:
        return {f.fingerprint() for f in self.new}

    @property
    def fixed_fingerprints(self) -> set[str]:
        return {f.fingerprint() for f in self.fixed}

    def summary(self) -> dict:
        return {
            "new": len(self.new),
            "fixed": len(self.fixed),
            "persisted": len(self.persisted),
        }


def compare(baseline: ScanResult, current: ScanResult) -> DiffResult:
    """Compare current scan against a baseline scan."""
    baseline_fps = {f.fingerprint(): f for f in baseline.findings}
    current_fps  = {f.fingerprint(): f for f in current.findings}

    new_fps       = set(current_fps) - set(baseline_fps)
    fixed_fps     = set(baseline_fps) - set(current_fps)
    persisted_fps = set(current_fps) & set(baseline_fps)

    return DiffResult(
        new=[current_fps[fp] for fp in new_fps],
        fixed=[baseline_fps[fp] for fp in fixed_fps],
        persisted=[current_fps[fp] for fp in persisted_fps],
    )
