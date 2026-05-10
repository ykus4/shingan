# Changelog

All notable changes to shingan are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
Versions align with [Semantic Versioning](https://semver.org/).

---

## [1.0.0] — 2026-05-10

### Added
- **MASVS/MASTG full mapping** — every `Finding` now carries a `masvs` field
  (e.g. `MASVS-NETWORK-1`, `MASVS-RESILIENCE-3`) shown in HTML reports and JSON output.
- **EN/JA report localization** — `--lang en|ja` on `shingan scan` and
  `to_html(..., lang=)` in the API; all UI strings (severity labels, section
  headers, diff badges) switch language.
- **Custom YAML rule engine** — load project-specific checks from
  `~/.shingan/rules/*.yaml`; supports `string`, `regex`, and `plist_key` match
  types targeting the binary string table or `Info.plist`.
- **SQLite storage** (`~/.shingan/shingan.db`) with automatic JSON migration from
  the v0.2 flat-file store.
- **Suppression / allowlist** — `SuppressionStore` backed by
  `~/.shingan/suppressions.json`; REST API and CLI both support add/remove/list.
- **Baseline pinning** — `POST /api/baselines/{app_id}` pins a scan as the
  reference; `shingan scan --baseline <id>` diffs against it.
- **GitHub Actions composite action** (`action/action.yml`) — drop-in SARIF
  upload to GitHub Code Scanning.
- **Fastlane plugin** (`fastlane-plugin-shingan`) — `shingan_scan` lane action.
- **Five new checkers**: `binary_protection` (PIE/stack-canary/ARC),
  `crypto` (MD5/SHA1/DES/RC4/ECB), `keychain` (weak `kSecAttrAccessible*`),
  `sbom` (SDK fingerprinting), `metadata` (background modes / permissions / ATS).
- **Diff/baseline comparison** in HTML reports — NEW / FIXED diff badges per finding.
- **SARIF 2.1.0 export** for GitHub Code Scanning integration.
- **`.app` directory and `.xcarchive` direct input** support.
- GitHub issue templates (bug report, false positive, new check) and PR template.
- `.pre-commit-config.yaml` with ruff lint + format hooks.
- CI workflow (lint + test) and scan workflow (workflow_dispatch).

### Changed
- `Finding` dataclass gains `masvs: str = ""` field (backwards-compatible).
- HTML report template (`report.html`) uses Jinja2 i18n variables; shows MASVS
  tag per finding; version bumped to 1.0.0 in footer.
- SARIF driver version updated to `1.0.0`.
- `pyproject.toml` version → `1.0.0`.

---

## [0.3.0] — 2026-04-28

### Added
- Web UI diff comparison and suppress operations.
- FastAPI REST API: `/api/suppressions`, `/api/baselines/{app_id}`.
- GitHub Actions composite action and Fastlane plugin stubs.

---

## [0.2.0] — 2026-04-14

### Added
- `.app` directory and `.xcarchive` input support.
- Five new checkers: `binary_protection`, `crypto`, `keychain`, `sbom`,
  `metadata`.
- Confidence scoring on `secrets` checker.
- Suppression allowlist (initial implementation).

---

## [0.1.0] — 2026-04-01

### Added
- Initial release.
- Core checkers: `symbols`, `secrets`, `ats`, `debug_flags`, `protection`.
- FastAPI web UI with drag-and-drop IPA upload.
- CLI (`shingan scan`, `list`, `diff`, `export`, `serve`).
- JSON scan storage.
- SARIF export.
- HTML report with dark-mode template.
