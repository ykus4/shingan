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
    type: string | regex | plist_key
    target: binary | info_plist      # binary = string table, info_plist = Info.plist
    patterns:
      - "SomeString"
      - "AnotherPattern"
    any: true   # true = at least one match triggers; false = all must match (default: true)
"""

from __future__ import annotations

import logging
import os
import re
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

from shingan.core.binary import AndroidCheckContext, CheckContext
from shingan.core.models import Finding, Severity

logger = logging.getLogger(__name__)

_SHINGAN_HOME = (
    Path(os.environ["SHINGAN_HOME"])
    if "SHINGAN_HOME" in os.environ
    else Path.home() / ".shingan"
)
DEFAULT_RULES_DIR = _SHINGAN_HOME / "rules"


def _load_yaml_rules(rules_dir: Path) -> list[dict]:
    if yaml is None:
        logger.warning("PyYAML not installed — custom rules disabled")
        return []
    rules: list[dict] = []
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
        except Exception as exc:
            logger.warning("Failed to load custom rule file %s: %s", path, exc)
    return rules


def _match_string(patterns: list[str], corpus: set[str], any_match: bool) -> list[str]:
    hits: list[str] = []
    matched_count = 0
    for pat in patterns:
        found = [s for s in corpus if pat in s]
        if found:
            hits.extend(found[:3])
            matched_count += 1
    if any_match:
        return hits[:10]
    return hits[:10] if matched_count == len(patterns) else []


def _match_regex(patterns: list[str], corpus: set[str], any_match: bool) -> list[str]:
    hits: list[str] = []
    matched_count = 0
    for pat in patterns:
        try:
            rx = re.compile(pat)
        except re.error as exc:
            logger.warning("Invalid regex in custom rule: %r — %s", pat, exc)
            continue
        found = [s for s in corpus if rx.search(s)]
        if found:
            hits.extend(found[:3])
            matched_count += 1
    if any_match and hits:
        return hits[:10]
    if not any_match and matched_count == len(patterns):
        return hits[:10]
    return []


def _match_plist_key(
    patterns: list[str], info_plist: dict, any_match: bool
) -> list[str]:
    hits: list[str] = []
    for pat in patterns:
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
    ctx: CheckContext | AndroidCheckContext,
    rules_dir: Path = DEFAULT_RULES_DIR,
) -> list[Finding]:
    rules = _load_yaml_rules(rules_dir)
    if not rules:
        return []

    findings: list[Finding] = []

    for rule in rules:
        rule_id = rule.get("id") or "CUSTOM-000"
        title = rule.get("title", rule_id)
        severity = Severity(rule.get("severity", "info"))
        description = rule.get("description", "")
        recommendation = rule.get("recommendation", "")
        masvs = rule.get("masvs", "")
        match_cfg = rule.get("match", {})

        match_type = match_cfg.get("type", "string")
        target = match_cfg.get("target", "binary")
        patterns: list[str] = match_cfg.get("patterns", [])
        any_match: bool = match_cfg.get("any", True)

        if not patterns:
            continue

        hits: list[str] = []

        if target == "binary":
            if match_type == "string":
                hits = _match_string(patterns, ctx.strings, any_match)
            elif match_type == "regex":
                hits = _match_regex(patterns, ctx.strings, any_match)
        elif target == "info_plist":
            plist = getattr(ctx, "info_plist", {})
            hits = _match_plist_key(patterns, plist, any_match)
        elif target == "android_manifest":
            manifest = _get_android_manifest_dict(ctx)
            hits = _match_plist_key(patterns, manifest, any_match)

        if hits:
            findings.append(
                Finding(
                    rule_id=rule_id,
                    title=title,
                    severity=severity,
                    description=description,
                    evidence="\n".join(hits),
                    recommendation=recommendation,
                    masvs=masvs,
                    extra={"custom": True},
                )
            )

    return findings


def _get_android_manifest_dict(ctx) -> dict:
    """Extract a flat key=value dict from an AndroidCheckContext's manifest for rule matching."""
    apk = getattr(ctx, "apk", None)
    if apk is None:
        return {}
    result: dict = {}
    try:
        result["package"] = apk.get_package() or ""
        result["versionName"] = apk.get_androidversion_name() or ""
        result["versionCode"] = str(apk.get_androidversion_code() or "")
        result["minSdkVersion"] = str(apk.get_min_sdk_version() or "")
        result["targetSdkVersion"] = str(apk.get_target_sdk_version() or "")
        result["debuggable"] = str(
            apk.get_attribute_value("application", "debuggable") or "false"
        )
        result["allowBackup"] = str(
            apk.get_attribute_value("application", "allowBackup") or "false"
        )
        result["permissions"] = " ".join(apk.get_permissions())
    except Exception:
        pass
    return result
