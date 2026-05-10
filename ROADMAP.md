# shingan — Roadmap

> **Concept**: Before "how do I obfuscate my app?", answer "where is my app exposed?" — shingan makes that visible.

---

## v0.1 — MVP (static analysis) ✅

### Checks (Must-have)
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

## v0.2 — Accuracy improvements

### New checks
- [ ] **IOS-RASP-006**: PIE enabled (`otool -hv`)
- [ ] **IOS-RASP-007**: Stack canary enabled
- [ ] **IOS-RASP-008**: ARC (Automatic Reference Counting) enabled
- [ ] **IOS-SEC-009**: Keychain access level (`kSecAttrAccessible*` usage)
- [ ] **IOS-SEC-010**: Weak crypto detection (MD5, SHA1, ECB mode, etc.)
- [ ] **IOS-DEP-011**: Third-party SDK vulnerability fingerprinting (SBOM)
- [ ] **IOS-META-012**: Over-privileged background modes / permissions

### Detection quality
- [ ] Secret validation layer (verify AWS key format, etc.)
- [ ] Two-stage confidence scoring (`pattern_score × validation_score`)
- [ ] False positive suppression (allowlist / per-finding suppress)
- [ ] Direct `.app` bundle and `xcarchive` input support

---

## v0.3 — UX and integrations

### Web UI
- [ ] Diff comparison UI — select two scans, highlight delta
- [ ] Per-finding suppress action
- [ ] PDF export
- [ ] Light mode theme

### CI/CD
- [ ] Official GitHub Actions action (`shingan/action@v1`)
- [ ] GitLab CI example
- [ ] Fastlane plugin
- [ ] JIRA / Slack webhook notifications

### API
- [ ] `POST /api/suppressions`
- [ ] `POST /api/baselines/{app_id}`
- [ ] Full OpenAPI docs

---

## v0.4 — Dynamic analysis (TODO)

> Static signals can only tell you whether a protection *indicator exists*.
> Confirming that a protection *actually works* requires dynamic testing.

- [ ] **Frida script integration**: attempt SSL pinning bypass → report result
- [ ] **objection integration**: attempt jailbreak detection bypass
- [ ] **PT_DENY_ATTACH effectiveness**: attempt LLDB attach → record outcome
- [ ] **Real device / Simulator mode**: `shingan scan --dynamic --device <udid>`
- [ ] Combined static + dynamic scoring

---

## v1.0 — Production-ready

- [ ] Multi-user support (auth / team workspaces)
- [ ] SQLite / PostgreSQL storage backend
- [ ] Custom YAML rule engine (user-defined checks)
- [ ] Full MASVS / MASTG checklist mapping
- [ ] Localization (English / Japanese reports)
- [ ] Docker image / Homebrew formula

---

## Differentiation

| Commercial tools | OSS tools | shingan targets |
|---|---|---|
| Broad coverage | Transparency & auditability | **Mobile-native UX + OSS-level observability** |
| CI integration | Highly customizable | **Explainable rules + diff management** |
| Black box | Requires setup | **Drop in an IPA, get results immediately** |

**Key differentiator**: clear diff output — "what changed since last build?" — so CI only fails on genuinely new findings, not accumulated backlog.
