# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**shingan** is a static security analysis tool for iOS IPA files. It detects reverse-engineering vulnerabilities and maps findings to OWASP MASVS standards. Interfaces: CLI, Web UI, and CI/CD integration (GitHub Actions, Fastlane).

## Commands

Requires [uv](https://docs.astral.sh/uv/installation/) as the package manager.

```bash
uv sync                        # Install dependencies
uv sync --dev                  # Include dev dependencies
uv run pre-commit install      # Set up commit hooks

uv run shingan scan MyApp.ipa  # Scan an IPA
uv run shingan serve           # Start Web UI at http://localhost:8000

uv run ruff check .            # Lint
uv run ruff format .           # Format
uv run pytest tests/ -v        # Run all tests
uv run pytest tests/ -k "test_name"  # Run a single test
```

Python version: 3.13+

## Architecture

```
CLI (click) / Web UI (FastAPI) / CI
          │
    analyzer.py              ← orchestrates everything
          │
    ingest.py                ← extracts IPA / .app / .xcarchive, parses Info.plist
          │
    binary.py (CheckContext) ← builds shared, lazily-cached state:
                               .strings, .lief_binary, .symbol_names, .objc_classes
          │
    checkers/ (10 modules)   ← each returns list[Finding]
          │
    rules.py                 ← applies custom YAML rules (~/.shingan/rules/*.yaml)
    suppression.py           ← filters suppressions (~/.shingan/suppressions.json)
          │
    storage.py               ← SQLite (~/.shingan/shingan.db); auto-migrates legacy JSON
    report.py                ← renders JSON / SARIF 2.1.0 / HTML (EN+JA) / text
```

### Checker pattern

Every checker in `shingan/core/checkers/` follows the same interface:

```python
def check(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    # use ctx.strings, ctx.lief_binary, ctx.info_plist, ctx.symbol_names, ...
    findings.append(Finding(
        rule_id="IOS-XXX-NNN",
        title="...",
        severity=Severity.HIGH,
        description="...",
        evidence="...",
        recommendation="...",
        masvs="MASVS-...",
    ))
    return findings
```

### Key data models (`core/models.py`)

- `Finding` — a single vulnerability hit (rule_id, severity, evidence, masvs, …)
- `ScanResult` — full scan output (app metadata + list of findings)
- `Severity` — enum: `CRITICAL / HIGH / MEDIUM / LOW / INFO`

### Storage

- Scan results: `~/.shingan/shingan.db` (SQLite)
- Custom rules: `~/.shingan/rules/*.yaml`
- Suppressions: `~/.shingan/suppressions.json`
- Legacy JSON scans in `~/.shingan/scans/` are auto-migrated on first run

## Checkers reference

| Rule ID | Module | What it checks |
|---|---|---|
| IOS-SYM-001 | symbols.py | Debug symbols, ObjC/Swift class names |
| IOS-SEC-002 | secrets.py | Hardcoded API keys, high-entropy strings |
| IOS-ATS-003 | ats.py | App Transport Security config |
| IOS-DBG-004 | debug_flags.py | Debug entitlements, NSLog usage |
| IOS-RASP-005 | protection.py | Jailbreak detection, Frida, SSL pinning |
| IOS-RASP-006/007/008 | binary_protection.py | PIE, stack canary, ARC |
| IOS-SEC-009 | keychain.py | Weak keychain access levels |
| IOS-SEC-010 | crypto.py | Weak crypto algorithms |
| IOS-DEP-011 | sbom.py | SDK fingerprinting |
| IOS-META-012 | metadata.py | Permissions, background modes |
