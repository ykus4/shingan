<div align="center">

<img src="docs/shingan_logo.png" alt="shingan" width="360" />

**Static + dynamic security analysis for iOS and Android apps**

Visualize where your app is exposed to reverse engineering — before you ship.

[![Python 3.13+](https://img.shields.io/badge/python-3.13%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![OWASP MASVS](https://img.shields.io/badge/mapped%20to-OWASP%20MASVS-orange)](https://mas.owasp.org/MASVS/)
[![CI](https://github.com/ykus4/shingan/actions/workflows/ci.yml/badge.svg)](https://github.com/ykus4/shingan/actions/workflows/ci.yml)

</div>

---

```
 .ipa / .app / .xcarchive          .apk
           │                         │
           └──────────┬──────────────┘
                      ▼
              ┌───────────────────┐
              │      shingan      │
              │  static checkers  │
              │  dynamic checks*  │
              └────────┬──────────┘
                       │
        ┌──────────────┼──────────────┐
        ▼              ▼              ▼
    terminal       HTML report     SARIF
    (rich table)   (EN / JA)       (GitHub Code Scanning)
```

> \* Dynamic analysis requires `pip install 'shingan[dynamic]'` (Frida).

---

## What it checks

<details open>
<summary><strong>iOS — static</strong> (IPA / .app / .xcarchive)</summary>

| Rule ID | Category | What it detects |
|---|---|---|
| `IOS-SYM-001` | Symbols | Debug symbols, ObjC class/method metadata, Swift mangled names |
| `IOS-SEC-002` | Secrets | Hardcoded API keys, tokens, HTTP URLs (regex + Shannon entropy) |
| `IOS-ATS-003` | Transport | `NSAllowsArbitraryLoads`, per-domain exceptions, weak TLS, file sharing |
| `IOS-DBG-004` | Debug | `get-task-allow` entitlement, `NSLog`/`print` strings, `NSAssertionsEnabled` |
| `IOS-RASP-005` | Protection | Jailbreak detection, Frida/LLDB anti-tamper, SSL pinning — presence or absence |
| `IOS-RASP-006` | Binary | PIE (Position Independent Executable) |
| `IOS-RASP-007` | Binary | Stack canary |
| `IOS-RASP-008` | Binary | ARC (Automatic Reference Counting) |
| `IOS-SEC-009` | Keychain | Weak `kSecAttrAccessible*` access levels |
| `IOS-SEC-010` | Crypto | MD5, SHA-1, DES/3DES, RC4, ECB mode |
| `IOS-DEP-011` | SBOM | Third-party SDK fingerprinting (Firebase, Stripe, OpenSSL, …) |
| `IOS-META-012` | Metadata | Over-privileged background modes, sensitive permissions, missing ATS |

</details>

<details open>
<summary><strong>iOS — dynamic</strong> (requires <code>shingan[dynamic]</code> + connected device)</summary>

| Rule ID | What it tests |
|---|---|
| `IOS-DYN-001` | SSL pinning bypass via Frida — does pinning actually block a MITM? |
| `IOS-DYN-002` | Jailbreak detection bypass via Frida — can detection be circumvented? |
| `IOS-DYN-003` | `PT_DENY_ATTACH` effectiveness — does LLDB attach succeed? |

</details>

<details open>
<summary><strong>Android — static</strong> (APK)</summary>

| Rule ID | Category | What it detects |
|---|---|---|
| `AND-SEC-002` | Secrets | Hardcoded credentials in DEX + native libraries (regex + entropy) |
| `AND-NET-003` | Transport | `cleartextTrafficPermitted`, user CA trust, missing pinning in `network_security_config.xml` |
| `AND-DBG-004` | Debug | `android:debuggable=true`, `Log.d`/`Log.v` calls in DEX |
| `AND-RASP-005` | Protection | Root detection, Frida/Xposed, debugger detection, SSL pinning — presence or absence |
| `AND-RASP-006` | Binary | PIE on bundled `.so` libraries |
| `AND-RASP-007` | Binary | NX bit, stack canary, RELRO on bundled `.so` libraries |
| `AND-SEC-010` | Crypto | Weak JCA/JCE: MD5, SHA-1, DES, ECB mode, RSA/PKCS1 |
| `AND-META-012` | Permissions | Dangerous permissions: SEND_SMS, READ_CALL_LOG, ACCESS_FINE_LOCATION, … |
| `AND-META-013` | Manifest | `android:allowBackup=true`, exported components without permission guard |
| `AND-DEP-011` | SBOM | SDK fingerprinting (Firebase, OkHttp, Sentry, Unity, Flutter, …) |
| `AND-SDK-015` | Manifest | `minSdkVersion` below API 23 |
| `AND-SIGN-014` | Signing | v1 (JAR) signing only — v2/v3 scheme not detected |

</details>

<details open>
<summary><strong>Android — dynamic</strong> (requires <code>shingan[dynamic]</code> + connected device)</summary>

| Rule ID | What it tests |
|---|---|
| `AND-DYN-001` | SSL unpinning bypass via Frida — hooks OkHttp3, TrustManager, HostnameVerifier |
| `AND-DYN-002` | Root detection bypass via Frida — hooks File.exists, Runtime.exec, Build.TAGS |

</details>

All findings are mapped to **[OWASP MASVS](https://mas.owasp.org/MASVS/)**.

Dynamic outcomes: `bypassed` (HIGH) · `resistant` (INFO) · `unavailable` (INFO) · `error` (MEDIUM)

---

## Installation

### From source

> Requires Python 3.13+ and **[uv](https://docs.astral.sh/uv/)**.

```bash
git clone https://github.com/ykus4/shingan.git
cd shingan
uv sync

# Enable dynamic analysis (Frida-based runtime checks)
uv sync --extra dynamic
```

### Docker

```bash
# Web UI
docker run -p 8000:8000 -v shingan-data:/data ghcr.io/ykus4/shingan

# CLI
docker run --rm \
  -v shingan-data:/data \
  -v /path/to/artifacts:/artifacts:ro \
  ghcr.io/ykus4/shingan \
  uv run shingan scan /artifacts/MyApp.ipa
```

---

## Usage

### Web UI

```bash
uv run shingan serve
# → http://localhost:8000
```

Drop an `.ipa`, `.app`, `.xcarchive`, or `.apk` onto the page. Results are stored locally and rendered as a dark/light-mode HTML report with diff highlighting.

---

### CLI

```bash
# Scan
uv run shingan scan MyApp.ipa
uv run shingan scan MyApp.apk

# Export formats
uv run shingan scan MyApp.ipa --format html --out report.html --lang ja
uv run shingan scan MyApp.apk --format sarif --out report.sarif
uv run shingan export <scan_id> --format pdf  --out report.pdf

# CI gate — exit 1 on new high-severity findings
uv run shingan scan MyApp.ipa --fail-on high

# Diff against a previous scan
uv run shingan scan MyApp.ipa --baseline <scan_id>

# Dynamic analysis (requires shingan[dynamic] + running app on device)
uv run shingan devices                                    # list connected devices + simulators
uv run shingan scan MyApp.ipa --dynamic                  # static + dynamic (iOS)
uv run shingan scan MyApp.apk --dynamic                  # static + dynamic (Android)
uv run shingan scan MyApp.ipa --dynamic --device <udid>  # target a specific device/simulator
```

---

### GitHub Actions

```yaml
- uses: ykus4/shingan@v1
  with:
    ipa: build/MyApp.ipa
    fail-on: high
    sarif-upload: true
```

<details>
<summary>Manual workflow</summary>

```yaml
- name: Scan
  run: uv run shingan scan build/MyApp.ipa --format sarif --out shingan.sarif --fail-on high

- name: Upload to GitHub Code Scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: shingan.sarif
```

</details>

---

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

| Format | Best for |
|---|---|
| `text` | Terminal — rich table with severity colors |
| `json` | Automation, custom dashboards |
| `sarif` | GitHub Code Scanning (SARIF 2.1.0) |
| `html` | Human review — self-contained dark/light-mode report, `--lang en\|ja` |
| `pdf` | Shareable reports |

---

## Diff / baseline

```
scan A  ──►  scan B
              │
              ├── NEW       ← regressions to fix
              ├── FIXED     ← improvements since last build
              └── PERSISTED ← known issues carried over
```

Run with `--baseline <scan_id>` to compare builds. `--fail-on` in CI only triggers on genuinely new regressions.

Scan results are stored in `~/.shingan/shingan.db` (SQLite).

---

## Suppression / allowlist

```bash
uv run shingan suppress add IOS-SEC-002-entropy --reason "test fixture key"
uv run shingan suppress add AND-SEC-002-aws_key --evidence-prefix AKIATEST --reason "CI test key"
uv run shingan suppress list
```

REST API: `POST /api/suppressions` · `GET /api/suppressions` · `DELETE /api/suppressions`

---

## Custom rules

Drop YAML files into `~/.shingan/rules/` to add project-specific checks:

```yaml
- id: MYAPP-001
  title: "Internal staging URL leaked in binary"
  severity: high
  description: "Staging endpoint found in release binary."
  recommendation: "Strip staging URLs before release builds."
  masvs: MASVS-NETWORK-1
  match:
    type: regex
    target: binary          # binary | info_plist | android_manifest
    patterns:
      - "https://staging\\.internal\\.example\\.com"
```

Match types: `string` (substring), `regex`, `plist_key` (dot-path lookup).

---

## Development

```bash
uv sync
uv run pre-commit install
uv run pytest
uv run pytest -k test_ats
```

---

## Changelog · Roadmap

- [CHANGELOG.md](docs/CHANGELOG.md)
- [ROADMAP.md](docs/ROADMAP.md)

---

<div align="center">

MIT License © [ykus4](https://github.com/ykus4)

</div>
