# shingan

**iOS IPA reverse-engineering exposure checker** — visualizes where your app is vulnerable to static analysis before you ship.

> Instead of "how do I obfuscate my app?", start with "where is my app exposed?" — shingan answers that.

---

## What it checks

| Rule ID | Category | What it detects |
|---|---|---|
| IOS-SYM-001 | Symbols | Debug symbols, Objective-C class/method metadata, Swift mangled symbols |
| IOS-SEC-002 | Secrets | Hardcoded API keys, tokens, plain HTTP URLs, endpoints (regex + Shannon entropy) |
| IOS-ATS-003 | ATS | `NSAllowsArbitraryLoads`, per-domain HTTP exceptions, weak TLS versions |
| IOS-DBG-004 | Debug flags | `get-task-allow` entitlement, `NSLog`/`print` strings in release binary |
| IOS-RASP-005 | Protection | Jailbreak detection, Frida/LLDB anti-tamper, SSL pinning — presence or absence |

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

Drag and drop an `.ipa` file to scan. Results are saved locally and shown in a dark-mode HTML report.

### CLI

```bash
# Scan an IPA, print results to terminal
uv run shingan scan MyApp.ipa

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

### CI/CD (GitHub Actions)

```yaml
- name: Scan IPA
  run: uv run shingan scan build/MyApp.ipa --format sarif --out shingan.sarif --fail-on high

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: shingan.sarif
```

---

## Output formats

| Format | Description |
|---|---|
| `text` | Rich terminal table (default) |
| `json` | Full structured output, saved to `~/.shingan/scans/` |
| `sarif` | SARIF 2.1.0 — compatible with GitHub Code Scanning |
| `html` | Self-contained dark-mode report with diff highlighting |

---

## Diff / baseline

shingan tracks findings across builds. Run with `--baseline <scan_id>` to see what is **new**, what was **fixed**, and what **persists** since the last scan. New findings are highlighted in the HTML report; only new findings trigger `--fail-on` in CI.

---

## Roadmap

See [ROADMAP.md](ROADMAP.md).

---

## License

MIT
