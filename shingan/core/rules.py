"""Custom YAML rule engine.

Rules are loaded from ~/.shingan/rules/*.yaml or a directory passed at runtime.

Rule schema:
  id: MY-RULE-001
  title: "My custom check"
  severity: critical | high | medium | low | info
  description: "What this detects"
  recommendation: "How to fix it"
  masvs: MASVS-RESILIENCE-1   # optional
  match:
    type: string | regex | plist_key
    target: binary | info_plist | android_manifest
    patterns:
      - "SomeString"
      - "AnotherPattern"
    any: true   # true = at least one match triggers; false = all must match (default: true)

A malformed rule is reported and skipped individually — one bad rule no longer
discards every other rule in the directory.

Trust boundary: rule files are authored by the operator and read from their own
``~/.shingan/rules`` directory, so they are trusted input — unlike the IPA/APK
under analysis.  Patterns are validated and compiled at load time, which
catches syntax errors early, but note that Python's ``re`` offers no match
timeout: a rule author can still write a pattern that backtracks
catastrophically against a large string corpus.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from shingan.core.constants import (
    RULE_HITS_PER_PATTERN,
    RULE_MAX_HITS,
)
from shingan.core.context import AndroidCheckContext, CheckContext
from shingan.core.models import Finding, Severity
from shingan.core.paths import default_rules_dir

logger = logging.getLogger(__name__)

MatchType = str
Target = str

_VALID_MATCH_TYPES = {"string", "regex", "plist_key"}
_VALID_TARGETS = {"binary", "info_plist", "android_manifest"}


class RuleError(ValueError):
    """Raised when a custom rule cannot be interpreted."""


@dataclass(frozen=True)
class RuleMatch:
    """The match clause of a custom rule."""

    match_type: MatchType
    target: Target
    patterns: tuple[str, ...]
    any_match: bool = True
    #: Pre-compiled patterns for ``type: regex``, compiled once at load time
    #: instead of on every scan.
    compiled: tuple[re.Pattern[str], ...] = field(default=())


@dataclass(frozen=True)
class Rule:
    """A validated custom rule."""

    rule_id: str
    title: str
    severity: Severity
    description: str
    recommendation: str
    masvs: str
    match: RuleMatch


def _parse_rule(raw: object, source: Path) -> Rule:
    """Validate one raw YAML mapping into a :class:`Rule`."""
    if not isinstance(raw, dict):
        raise RuleError(f"rule must be a mapping, got {type(raw).__name__}")

    rule_id = str(raw.get("id") or "").strip()
    if not rule_id:
        raise RuleError("rule is missing a non-empty 'id'")

    severity_raw = str(raw.get("severity", "info")).lower()
    try:
        severity = Severity(severity_raw)
    except ValueError as exc:
        valid = ", ".join(s.value for s in Severity)
        raise RuleError(
            f"invalid severity {severity_raw!r} (expected one of: {valid})"
        ) from exc

    match_cfg = raw.get("match") or {}
    if not isinstance(match_cfg, dict):
        raise RuleError("'match' must be a mapping")

    match_type = str(match_cfg.get("type", "string")).lower()
    if match_type not in _VALID_MATCH_TYPES:
        raise RuleError(
            f"invalid match type {match_type!r} "
            f"(expected one of: {', '.join(sorted(_VALID_MATCH_TYPES))})"
        )

    target = str(match_cfg.get("target", "binary")).lower()
    if target not in _VALID_TARGETS:
        raise RuleError(
            f"invalid match target {target!r} "
            f"(expected one of: {', '.join(sorted(_VALID_TARGETS))})"
        )

    raw_patterns = match_cfg.get("patterns") or []
    if not isinstance(raw_patterns, list) or not raw_patterns:
        raise RuleError("'match.patterns' must be a non-empty list")
    patterns = tuple(str(p) for p in raw_patterns)

    compiled: tuple[re.Pattern[str], ...] = ()
    if match_type == "regex":
        built: list[re.Pattern[str]] = []
        for pattern in patterns:
            try:
                built.append(re.compile(pattern))
            except re.error as exc:
                raise RuleError(f"invalid regex {pattern!r}: {exc}") from exc
        compiled = tuple(built)

    logger.debug("Loaded custom rule %s from %s", rule_id, source)
    return Rule(
        rule_id=rule_id,
        title=str(raw.get("title") or rule_id),
        severity=severity,
        description=str(raw.get("description", "")),
        recommendation=str(raw.get("recommendation", "")),
        masvs=str(raw.get("masvs", "")),
        match=RuleMatch(
            match_type=match_type,
            target=target,
            patterns=patterns,
            any_match=bool(match_cfg.get("any", True)),
            compiled=compiled,
        ),
    )


def load_rules(rules_dir: Path) -> list[Rule]:
    """Load and validate every rule file in ``rules_dir``.

    Invalid rules are logged and skipped; valid rules in the same file still
    load.
    """
    if not rules_dir.exists():
        return []

    rules: list[Rule] = []
    paths = sorted(rules_dir.glob("*.yaml")) + sorted(rules_dir.glob("*.yml"))
    for path in paths:
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            logger.warning("Failed to read custom rule file %s: %s", path, exc)
            continue

        entries = data if isinstance(data, list) else [data]
        for entry in entries:
            if entry is None:
                continue
            try:
                rules.append(_parse_rule(entry, path))
            except RuleError as exc:
                logger.warning("Skipping invalid rule in %s: %s", path, exc)
    return rules


def _cap(hits: list[str]) -> list[str]:
    return hits[:RULE_MAX_HITS]


def _match_literal(
    patterns: tuple[str, ...], corpus: set[str], any_match: bool
) -> list[str]:
    hits: list[str] = []
    matched = 0
    for pattern in patterns:
        found = [s for s in corpus if pattern in s]
        if found:
            hits.extend(sorted(found)[:RULE_HITS_PER_PATTERN])
            matched += 1
    if any_match:
        return _cap(hits)
    return _cap(hits) if matched == len(patterns) else []


def _match_regex(
    compiled: tuple[re.Pattern[str], ...], corpus: set[str], any_match: bool
) -> list[str]:
    hits: list[str] = []
    matched = 0
    for regex in compiled:
        found = [s for s in corpus if regex.search(s)]
        if found:
            hits.extend(sorted(found)[:RULE_HITS_PER_PATTERN])
            matched += 1
    if any_match:
        return _cap(hits)
    return _cap(hits) if matched == len(compiled) else []


def _match_keys(patterns: tuple[str, ...], mapping: dict, any_match: bool) -> list[str]:
    """Resolve dotted key paths against a nested mapping."""
    hits: list[str] = []
    for pattern in patterns:
        node: Any = mapping
        for part in pattern.split("."):
            if isinstance(node, dict):
                node = node.get(part)
            else:
                node = None
                break
        if node is not None:
            hits.append(f"{pattern} = {node!r}")
    if any_match:
        return hits
    return hits if len(hits) == len(patterns) else []


def _corpus_for(ctx: CheckContext | AndroidCheckContext) -> set[str]:
    """Text corpus used by ``target: binary``.

    For Android this covers DEX constants as well as native library strings —
    previously only the ``.so`` strings were searched, so rules silently missed
    anything defined in Java/Kotlin.
    """
    if isinstance(ctx, AndroidCheckContext):
        return ctx.all_text
    return ctx.strings


def _evaluate(rule: Rule, ctx: CheckContext | AndroidCheckContext) -> list[str]:
    match = rule.match
    if match.target == "binary":
        corpus = _corpus_for(ctx)
        if match.match_type == "regex":
            return _match_regex(match.compiled, corpus, match.any_match)
        return _match_literal(match.patterns, corpus, match.any_match)

    if match.target == "info_plist":
        plist = getattr(ctx, "info_plist", {}) or {}
        return _match_keys(match.patterns, plist, match.any_match)

    if match.target == "android_manifest":
        # Cached on the context, so N manifest rules no longer rebuild the
        # manifest summary N times.
        manifest = getattr(ctx, "manifest_summary", {}) or {}
        return _match_keys(match.patterns, manifest, match.any_match)

    return []


def apply_custom_rules(
    ctx: CheckContext | AndroidCheckContext,
    rules_dir: Path | None = None,
) -> list[Finding]:
    """Evaluate every custom rule against ``ctx``.

    Applies to both iOS and Android contexts; Android scans previously skipped
    custom rules entirely.
    """
    resolved_dir = rules_dir if rules_dir is not None else default_rules_dir()
    rules = load_rules(resolved_dir)
    if not rules:
        return []

    findings: list[Finding] = []
    for rule in rules:
        try:
            hits = _evaluate(rule, ctx)
        except Exception:
            logger.exception("Custom rule %s raised — skipping", rule.rule_id)
            continue
        if not hits:
            continue
        findings.append(
            Finding(
                rule_id=rule.rule_id,
                title=rule.title,
                severity=rule.severity,
                description=rule.description,
                evidence="\n".join(hits),
                recommendation=rule.recommendation,
                masvs=rule.masvs,
                extra={"custom": True},
            )
        )
    return findings
