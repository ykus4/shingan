# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**shingan** is a static security analysis tool for iOS (IPA) and Android (APK) apps. It detects reverse-engineering vulnerabilities and maps findings to OWASP MASVS standards. It can also run optional *dynamic* checks against a live device via frida. Interfaces: CLI, Web UI, and CI/CD integration (GitHub Actions, Fastlane).

## Commands

Requires [uv](https://docs.astral.sh/uv/installation/) as the package manager.

```bash
uv sync                        # Install dependencies
uv sync --dev                  # Include dev dependencies
uv run pre-commit install      # Set up commit hooks

uv run shingan scan MyApp.ipa  # Scan an IPA (also .app, .xcarchive, .apk)
uv run shingan serve           # Start Web UI at http://127.0.0.1:8000

uv run ruff check .            # Lint
uv run ruff format .           # Format
uv run mypy                    # Type check
uv run pytest tests/ -v        # Run all tests
uv run pytest tests/ -k "test_name"       # Run a single test
uv run pytest --cov --cov-report=term-missing   # Coverage
```

Python version: 3.13+

## Architecture

```
shingan/
├── cli.py                   ← Click CLI entry point
├── web/
│   ├── main.py              ← FastAPI app (serve command)
│   └── templates/           ← Jinja2 HTML templates
└── core/
    ├── analyzer.py          ← orchestrates a scan; dispatches iOS vs Android
    ├── ingest.py            ← extracts IPA / APK, parses manifests
    ├── archive.py           ← hardened zip extraction (size/ratio/member budgets)
    ├── context.py           ← CheckContext (iOS) + AndroidCheckContext (lazy-cached)
    ├── models.py            ← Finding, ScanResult, Severity
    ├── constants.py         ← all magic numbers / thresholds
    ├── paths.py             ← single source for ~/.shingan locations
    ├── version.py           ← single source for the package version
    ├── shell.py             ← the one subprocess wrapper (run_command)
    ├── entropy.py           ← Shannon entropy helpers
    ├── rules.py             ← custom YAML rules (~/.shingan/rules/*.yaml)
    ├── suppression.py       ← suppressions (~/.shingan/suppressions.json)
    ├── storage.py           ← SQLite (~/.shingan/shingan.db)
    ├── diff.py              ← baseline comparison
    ├── notify.py            ← Slack / JIRA webhooks for new HIGH findings
    ├── report.py            ← JSON / SARIF 2.1.0 / HTML (EN+JA) / PDF / text
    ├── checkers/
    │   ├── registry.py      ← auto-discovers checkers; run_checkers()
    │   ├── common/          ← platform-agnostic detection (secrets_engine)
    │   ├── ios/             ← iOS checkers (CheckContext)
    │   └── android/         ← Android checkers (AndroidCheckContext)
    └── dynamic/             ← optional frida-based on-device checks
        ├── runner.py        ← run_dynamic_checks()
        ├── device.py        ← device/simulator/emulator enumeration
        ├── context.py       ← DynamicContext (frida session)
        ├── checks/          ← dynamic checks (IOS-DYN-*, AND-DYN-*)
        └── scripts/         ← frida JS payloads
```

### Checker pattern

Every checker module in `checkers/ios/` or `checkers/android/` exposes a
module-level `check(ctx)` and is **discovered automatically** by
`checkers/registry.py` — adding a checker means adding one file, with no
registration step anywhere else.

```python
def check(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    # use ctx.strings, ctx.long_strings, ctx.lief_binary, ctx.info_plist, ctx.symbol_names, ...
    findings.append(
        Finding(
            rule_id="IOS-XXX-NNN",
            title="...",
            severity=Severity.HIGH,
            description="...",
            evidence="...",
            recommendation="...",
            masvs="MASVS-...",
        )
    )
    return findings
```

Rules of the road for checkers:

- **Never re-run `strings` or re-parse the binary.** Use the cached context
  properties (`ctx.strings`, `ctx.long_strings`, `ctx.all_text`,
  `ctx.lief_binary`, `ctx.dex_strings`, `ctx.manifest_summary`).
- **Shell out only via `core.shell.run_command`**, never `subprocess.run`.
- **Never swallow an exception silently** — log it. `S110` is enforced by ruff.
- Put thresholds and sample sizes in `core/constants.py`, not inline.
- Detection logic shared between platforms belongs in `checkers/common/`.
  The Android checker must not import from the iOS package.

### Key data models (`core/models.py`)

- `Finding` — a single vulnerability hit (rule_id, severity, evidence, masvs, …)
- `ScanResult` — full scan output (app metadata + list of findings)
- `Severity` — `StrEnum`: `CRITICAL / HIGH / MEDIUM / LOW / INFO`.
  Use `severity.rank` for ordering, `severity.color` for terminal output, and
  `severity.at_least(threshold)` for gating — do not build ad-hoc order tables.

`ScanResult.artifact_name` is the field name; JSON output emits **both**
`artifact_name` and the legacy `ipa_name` key for backward compatibility.

### Storage

- Scan results: `~/.shingan/shingan.db` (SQLite, version tracked in `schema_meta`)
- Custom rules: `~/.shingan/rules/*.yaml`
- Suppressions: `~/.shingan/suppressions.json`
- Legacy JSON scans in `~/.shingan/scans/` are imported once, then the directory
  is renamed to `scans.migrated`
- All locations derive from `core/paths.py` and honour `$SHINGAN_HOME`, which is
  resolved **on every call** so tests and embedders can override it

### Untrusted input

The IPA/APK under analysis is adversarial input. Accordingly:

- archives go through `core.archive.safe_extract_zip` (size, ratio and member
  budgets; `zipfile` alone has none)
- XML from an APK is parsed with `defusedxml`, not `xml.etree` (which expands
  internal entities)
- `CFBundleExecutable` is checked for path escape before use
- uploaded filenames are reduced with `core.archive.safe_filename`

Custom rule files in `~/.shingan/rules` are *operator-authored* and therefore
trusted; note that Python's `re` has no match timeout.

### Web API

Stores are injected as FastAPI dependencies (`get_store`, `get_suppression_store`)
so importing `shingan.web.main` has no filesystem side effects and tests can
override them. Mutating endpoints require `X-API-Key` **when `SHINGAN_API_KEY`
is set**; with it unset the API is open, which is why `serve` binds `127.0.0.1`
by default.

## Checkers reference

Rule-ID prefixes: `IOS-*` (static iOS), `AND-*` (static Android),
`IOS-DYN-*` / `AND-DYN-*` (dynamic).

| Module (`checkers/ios/`) | Rule IDs | What it checks |
|---|---|---|
| symbols.py | IOS-SYM-001 | Debug symbols, ObjC/Swift class names |
| secrets.py | IOS-SEC-002 | Hardcoded API keys, high-entropy strings |
| ats.py | IOS-ATS-003 | App Transport Security config |
| debug_flags.py | IOS-DBG-004 | Debug entitlements, NSLog usage |
| protection.py | IOS-RASP-005 | Jailbreak detection, Frida, SSL pinning |
| binary_protection.py | IOS-RASP-006/007/008 | PIE, stack canary, ARC |
| keychain.py | IOS-SEC-009 | Weak keychain access levels |
| crypto.py | IOS-SEC-010 | Weak crypto algorithms |
| sbom.py | IOS-DEP-011 | SDK fingerprinting |
| metadata.py | IOS-META-012, IOS-URL-018 | Permissions, background modes, URL schemes |
| data_handling.py | IOS-CODE-019 | Insecure data handling / storage |
| webview.py | IOS-WEB-* | WKWebView configuration |

| Module (`checkers/android/`) | What it checks |
|---|---|
| manifest.py | allowBackup, exported components, minSdkVersion |
| debug_flags.py | `android:debuggable`, logging calls |
| network_security.py | Network Security Config (cleartext, user CAs, pinning) |
| binary_protection.py | Native `.so` hardening (RELRO, canary, PIE) |
| crypto.py | Weak crypto algorithms |
| secrets.py | Hardcoded secrets in DEX + native strings |
| protection.py | Root detection, Frida, emulator detection |
| permissions.py | Dangerous permission declarations |
| sbom.py | SDK fingerprinting |
| signing.py | APK signature scheme (v1/v2/v3) |
| webview.py | WebView configuration |
| data_handling.py | Insecure storage / data handling |

Since checkers are auto-discovered, this table is documentation only — the
authoritative list is whatever modules exist in those two directories.
