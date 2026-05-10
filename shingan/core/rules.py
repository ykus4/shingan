"""Custom YAML rule engine.

Rules are loaded from ~/.shingan/rules/*.yaml or a directory passed at runtime.

Rule schema:
  id: MY-RULE-001
  title: "My custom check"
  severity: high | medium | low | info
  description: "What this detects"
  recommendation: "How to fix it"
  masvs: MASVS-RESILIENCE-1   # optional
  match:
    type: string | regex | plist_key | symbol
    target: binary | info_plist      # binary = string table, info_plist = Info.plist
    patterns:
      - "SomeString"
      - "AnotherPattern"
    any: true   # true = at least one match triggers; false = all must match (default: true)
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

from shingan.core.models import Finding, Severity

DEFAULT_RULES_DIR = Path.home() / ".shingan" / "rules"


def _load_yaml_rules(rules_dir: Path) -> list[dict]:
    if yaml is None:
        return []
    rules = []
    if not rules_dir.exists():
        return rules
    for path in sorted(rules_dir.glob("*.yaml")) + sorted(rules_dir.glob("*.yml")):
        try:
            with open(path) as f:
                data = yaml.safe_load(f)
            if isinstance(data, list):
                rules.extend(data)
            elif isinstance(data, dict):
                rules.append(data)
        except Exception:
            continue
    return rules


def _get_strings(binary_path: Path) -> set[str]:
    try:
        result = subprocess.run(
            ["strings", "-a", "-n", "5", str(binary_path)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        return set(result.stdout.splitlines())
    except Exception:
        return set()


def _match_string(patterns: list[str], corpus: set[str], any_match: bool) -> list[str]:
    hits = []
    for pat in patterns:
        matched = [s for s in corpus if pat in s]
        if matched:
            hits.extend(matched[:3])
    if any_match:
        return hits[:10]
    # all-match: every pattern must appear
    if len(hits) >= len(patterns):
        return hits[:10]
    return []


def _match_regex(patterns: list[str], corpus: set[str], any_match: bool) -> list[str]:
    hits = []
    matched_patterns = 0
    for pat in patterns:
        try:
            rx = re.compile(pat)
        except re.error:
            continue
        found = [s for s in corpus if rx.search(s)]
        if found:
            hits.extend(found[:3])
            matched_patterns += 1
    if any_match and hits:
        return hits[:10]
    if not any_match and matched_patterns == len(patterns):
        return hits[:10]
    return []


def _match_plist_key(
    patterns: list[str], info_plist: dict, any_match: bool
) -> list[str]:
    hits = []
    for pat in patterns:
        # Support dot-notation: "NSAppTransportSecurity.NSAllowsArbitraryLoads"
        parts = pat.split(".")
        node: Any = info_plist
        for part in parts:
            if isinstance(node, dict):
                node = node.get(part)
            else:
                node = None
                break
        if node is not None:
            hits.append(f"{pat} = {node!r}")
    if any_match and hits:
        return hits
    if not any_match and len(hits) == len(patterns):
        return hits
    return []


def apply_custom_rules(
    binary_path: Path,
    info_plist: dict,
    rules_dir: Path = DEFAULT_RULES_DIR,
) -> list[Finding]:
    rules = _load_yaml_rules(rules_dir)
    if not rules:
        return []

    findings: list[Finding] = []
    strings: set[str] | None = None

    for rule in rules:
        rule_id = rule.get("id", "CUSTOM-000")
        title = rule.get("title", rule_id)
        severity = Severity(rule.get("severity", "info"))
        description = rule.get("description", "")
        recommendation = rule.get("recommendation", "")
        masvs = rule.get("masvs", "")
        match_cfg = rule.get("match", {})

        match_type = match_cfg.get("type", "string")
        target = match_cfg.get("target", "binary")
        patterns = match_cfg.get("patterns", [])
        any_match = match_cfg.get("any", True)

        if not patterns:
            continue

        hits: list[str] = []

        if target == "binary":
            if strings is None:
                strings = _get_strings(binary_path)
            if match_type == "string":
                hits = _match_string(patterns, strings, any_match)
            elif match_type == "regex":
                hits = _match_regex(patterns, strings, any_match)
        elif target == "info_plist":
            hits = _match_plist_key(patterns, info_plist, any_match)

        if hits:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    description=description,
                    evidence="\n".join(hits),
                    recommendation=recommendation,
                    extra={"masvs": masvs, "custom": True},
                )
            )

    return findings
