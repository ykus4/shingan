# shingan — Roadmap

> **Concept**: Before "how do I obfuscate my app?", answer "where is my app exposed?" — shingan makes that visible.

---

## v0.1 — MVP (static analysis) ✅

### Checks
| Rule ID | What it detects | Status |
|---|---|---|
| IOS-SYM-001 | Debug symbols, ObjC class metadata, Swift mangled symbols | ✅ |
| IOS-SEC-002 | Hardcoded API keys / secrets (regex + entropy) | ✅ |
| IOS-SEC-002 | Hardcoded URLs / endpoints | ✅ |
| IOS-DBG-004 | Debug flags in release binary (entitlements, NSLog strings) | ✅ |
| IOS-ATS-003 | ATS misconfiguration (NSAllowsArbitraryLoads, etc.) | ✅ |
| IOS-RASP-005 | Jailbreak detection — present or absent | ✅ |
| IOS-RASP-005 | Frida / LLDB anti-tamper — present or absent | ✅ |
| IOS-RASP-005 | SSL pinning — present or absent | ✅ |

### Infrastructure
- [x] FastAPI + web UI (drag-and-drop IPA upload → results)
- [x] CLI (`scan`, `list`, `diff`, `export`, `serve`)
- [x] JSON / SARIF / HTML report output
- [x] Diff / baseline comparison (new / fixed / persisted)
- [x] JSON file storage (`~/.shingan/scans/`)
- [x] CI/CD support (`--fail-on high`)

---

## v0.2 — Accuracy improvements ✅

### New checks
| Rule ID | What it detects | Status |
|---|---|---|
| IOS-RASP-006 | PIE (Position Independent Executable) | ✅ |
| IOS-RASP-007 | Stack canary | ✅ |
| IOS-RASP-008 | ARC (Automatic Reference Counting) | ✅ |
| IOS-SEC-009 | Weak Keychain access levels (`kSecAttrAccessible*`) | ✅ |
| IOS-SEC-010 | Weak crypto: MD5, SHA-1, DES/3DES, RC4, ECB mode | ✅ |
| IOS-DEP-011 | Third-party SDK fingerprinting (SBOM) | ✅ |
| IOS-META-012 | Over-privileged background modes / permissions | ✅ |

### Detection quality
- [x] Secret validation layer (regex + entropy confidence scoring)
- [x] False positive suppression (allowlist / per-finding suppress)
- [x] Direct `.app` bundle and `.xcarchive` input support

---

## v0.3 — UX and integrations ✅

### Web UI
- [x] Diff comparison UI — NEW / FIXED badges per finding
- [x] Per-finding suppress action (via API)

### CI/CD
- [x] Official GitHub Actions composite action (`action/action.yml`)
- [x] Fastlane plugin (`fastlane-plugin-shingan`)

### API
- [x] `POST /api/suppressions`
- [x] `POST /api/baselines/{app_id}`

---

## v1.0 — Production-ready ✅

- [x] SQLite storage (`~/.shingan/shingan.db`) with auto JSON migration
- [x] Custom YAML rule engine (`~/.shingan/rules/*.yaml`)
- [x] Full MASVS / MASTG checklist mapping on all findings
- [x] EN / JA report localization (`--lang en|ja`)
- [x] SARIF 2.1.0 export for GitHub Code Scanning
- [x] 32-test suite covering all checkers, suppression, diff, report generation

---

## v1.1 — Polish ✅

- [x] PDF export from HTML report
- [x] Light mode theme option
- [x] GitLab CI example workflow
- [x] JIRA / Slack webhook notifications on new HIGH findings
- [x] `shingan suppress` CLI subcommand (wraps REST API)
- [x] OpenAPI docs auto-generated at `/docs`

---

## v1.2 — Dynamic analysis ✅

> Static signals can only tell you whether a protection *indicator exists*.
> Confirming that a protection *actually works* requires dynamic testing.

- [x] **Frida script integration**: attempt SSL pinning bypass → report result (IOS-DYN-001)
- [x] **Frida script integration**: attempt jailbreak detection bypass → report result (IOS-DYN-002)
- [x] **PT_DENY_ATTACH effectiveness**: attempt LLDB attach → record outcome (IOS-DYN-003)
- [x] **Real device / Simulator mode**: `shingan scan --dynamic --device <udid>`, `shingan devices`
- [x] Combined static + dynamic scoring (`summary.static` / `summary.dynamic` breakdown)

Install dynamic extras: `pip install 'shingan[dynamic]'`

---

## Future

- [ ] Multi-user support (auth / team workspaces)
- [ ] PostgreSQL storage backend option
- [ ] Docker image / Homebrew formula
- [ ] VS Code extension

---

## Differentiation

| Commercial tools | OSS tools | shingan targets |
|---|---|---|
| Broad coverage | Transparency & auditability | **Mobile-native UX + OSS-level observability** |
| CI integration | Highly customizable | **Explainable rules + diff management** |
| Black box | Requires setup | **Drop in an IPA, get results immediately** |

**Key differentiator**: clear diff output — "what changed since last build?" — so CI only fails on genuinely new findings, not accumulated backlog.
