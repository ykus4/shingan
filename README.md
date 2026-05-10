# shingan

**iOS IPA reverse-engineering exposure checker** — visualizes where your app is vulnerable to static analysis before you ship.

> Instead of "how do I obfuscate my app?", start with "where is my app exposed?" — shingan answers that.

---

## What it checks

| Rule ID | Category | What it detects |
|---|---|---|
| IOS-SYM-001 | Symbols | Debug symbols, Objective-C class/method metadata, Swift mangled symbols |
| IOS-SEC-002 | Secrets | Hardcoded API keys, tokens, plain HTTP URLs, endpoints (regex + Shannon entropy) |
| IOS-ATS-003 | ATS | `NSAllowsArbitraryLoads`, per-domain HTTP exceptions, weak TLS, file sharing |
| IOS-DBG-004 | Debug flags | `get-task-allow` entitlement, `NSLog`/`print` strings, `NSAssertionsEnabled` |
| IOS-RASP-005 | Protection | Jailbreak detection, Frida/LLDB anti-tamper, SSL pinning — presence or absence |
| IOS-RASP-006 | Binary | PIE (Position Independent Executable) |
| IOS-RASP-007 | Binary | Stack canary |
| IOS-RASP-008 | Binary | ARC (Automatic Reference Counting) |
| IOS-SEC-009 | Keychain | Weak `kSecAttrAccessible*` values |
| IOS-SEC-010 | Crypto | Deprecated algorithms: MD5, SHA-1, DES/3DES, RC4, ECB mode |
| IOS-DEP-011 | SBOM | Third-party SDK fingerprinting (Firebase, Stripe, JSPatch, OpenSSL, etc.) |
| IOS-META-012 | Metadata | Over-privileged background modes, sensitive permissions, missing ATS config |

All findings are mapped to [OWASP MASVS](https://mas.owasp.org/MASVS/).

---

## Installation

Requires Python 3.13+ and [uv](https://docs.astral.sh/uv/).

```bash
git clone https://github.com/ykus4/shingan.git
cd shingan
uv sync
```

---

## Usage

### Web UI

```bash
uv run shingan serve
# → http://localhost:8000
```

Drag and drop an `.ipa`, `.app`, or `.xcarchive` to scan. Results are saved locally and shown in a dark-mode HTML report with diff highlighting.

### CLI

```bash
# Scan an IPA, print results to terminal
uv run shingan scan MyApp.ipa

# Output HTML report in Japanese
uv run shingan scan MyApp.ipa --format html --out report.html --lang ja

# Output SARIF for GitHub Code Scanning
uv run shingan scan MyApp.ipa --format sarif --out report.sarif

# Fail CI on high severity findings
uv run shingan scan MyApp.ipa --fail-on high

# Compare against a previous scan (diff mode)
uv run shingan scan MyApp.ipa --baseline <scan_id>

# List stored scans
uv run shingan list

# Show diff between two stored scans
uv run shingan diff <scan_id> <baseline_id>

# Export a stored scan
uv run shingan export <scan_id> --format html --out report.html
```

### GitHub Actions — composite action

```yaml
- uses: ykus4/shingan@v1
  with:
    ipa: build/MyApp.ipa
    fail-on: high
    sarif-upload: true
```

Or manually:

```yaml
- name: Scan IPA
  run: uv run shingan scan build/MyApp.ipa --format sarif --out shingan.sarif --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: shingan.sarif
```

### Fastlane

```ruby
lane :security_check do
  shingan_scan(
    ipa: "build/MyApp.ipa",
    fail_on: "high",
    output_format: "html",
    output_path: "shingan_report.html"
  )
end
```

---

## Output formats

| Format | Description |
|---|---|
| `text` | Rich terminal table (default) |
| `json` | Full structured output with MASVS mappings |
| `sarif` | SARIF 2.1.0 — compatible with GitHub Code Scanning |
| `html` | Self-contained dark-mode report, English or Japanese (`--lang en\|ja`) |

---

## Diff / baseline

shingan tracks findings across builds. Run with `--baseline <scan_id>` to see what is **new**, what was **fixed**, and what **persists** since the last scan. New findings are highlighted in the HTML report; `--fail-on` in CI only triggers on genuinely new findings.

Scan results are stored in `~/.shingan/shingan.db` (SQLite). Legacy JSON scans are auto-migrated on first run.

---

## Suppression / allowlist

Suppress known-false-positive findings so they don't block CI:

```bash
# Suppress by rule ID
uv run shingan suppress add IOS-SEC-002-entropy --reason "test fixture key"

# Suppress a specific evidence match
uv run shingan suppress add IOS-SEC-002-aws_key --evidence-prefix AKIATEST --reason "CI test key"

# List suppressions
uv run shingan suppress list
```

Via REST API: `POST /api/suppressions`, `GET /api/suppressions`, `DELETE /api/suppressions/{id}`.

---

## Custom rules

Drop YAML files into `~/.shingan/rules/` to add project-specific checks:

```yaml
# ~/.shingan/rules/my_checks.yaml
- id: MYAPP-001
  title: "Internal staging URL in binary"
  severity: high
  description: "Staging endpoint found in release binary."
  recommendation: "Strip staging URLs before release builds."
  masvs: MASVS-NETWORK-1
  match:
    type: regex
    target: binary
    patterns:
      - "https://staging\\.internal\\.example\\.com"
```

Supported match types: `string`, `regex`, `plist_key`. Targets: `binary` (string table) or `info_plist`.

---

## Development

```bash
uv sync
uv run pre-commit install
uv run pytest
```

Pre-commit runs ruff lint + format on every commit.

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md).

## Roadmap

See [ROADMAP.md](ROADMAP.md).

---

## License

MIT
