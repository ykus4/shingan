# shingan — ROADMAP

> **コンセプト**: 「難読化するツール」より前に「どこが解析されやすいか可視化するツール」

---

## v0.1 — MVP (静的解析) ✅

### チェック項目 (Must)
| Rule ID | 内容 | 実装 |
|---|---|---|
| IOS-SYM-001 | シンボル残存 (debug symbols / ObjC metadata / Swift symbols) | ✅ |
| IOS-SEC-002 | APIキー・シークレット平文埋め込み (regex + entropy) | ✅ |
| IOS-SEC-002 | URL / endpoint 露出 | ✅ |
| IOS-DBG-004 | Debug flag残存 (entitlements / NSLog strings) | ✅ |
| IOS-ATS-003 | ATS設定不備 (NSAllowsArbitraryLoads 等) | ✅ |
| IOS-RASP-005 | Jailbreak検知 指標有無 | ✅ |
| IOS-RASP-005 | Frida / LLDB対策 指標有無 | ✅ |
| IOS-RASP-005 | SSL Pinning 指標有無 | ✅ |

### インフラ
- [x] FastAPI + Web UI (IPA upload → 結果表示)
- [x] CLI (`shingan scan`, `shingan list`, `shingan diff`, `shingan export`, `shingan serve`)
- [x] JSON / SARIF / HTML レポート出力
- [x] diff/baseline比較 (新規/修正/継続の分類)
- [x] JSONファイルストレージ (`~/.shingan/scans/`)
- [x] CI/CD対応 (`--fail-on high`)

---

## v0.2 — チェック精度の向上

### チェック追加
- [ ] **IOS-RASP-006**: Binary protection flags — PIE有効化確認 (`otool -hv`)
- [ ] **IOS-RASP-007**: Stack canary有効化確認
- [ ] **IOS-RASP-008**: ARC (Automatic Reference Counting) 有効確認
- [ ] **IOS-SEC-009**: Keychain保護レベル確認 (kSecAttrAccessible* の使用箇所)
- [ ] **IOS-SEC-010**: 弱い暗号アルゴリズム使用検出 (MD5, SHA1, ECB mode等)
- [ ] **IOS-DEP-011**: 既知脆弱性を持つサードパーティSDK検出 (SBOM fingerprinting)
- [ ] **IOS-META-012**: バックグラウンドモード・過剰なpermission検出

### 精度向上
- [ ] シークレット検出に validation レイヤー追加 (AWS key フォーマット検証等)
- [ ] confidence score 導入 (pattern_score × validation_score)
- [ ] false positive 抑制リスト (allowlist/suppression)
- [ ] xcarchive / .app バンドル直接入力対応

---

## v0.3 — UX / 統合強化

### Web UI
- [ ] スキャン一覧でのdiff比較UI (バージョン選択 → 差分ハイライト)
- [ ] ファインディングごとのsuppress操作
- [ ] PDF エクスポート
- [ ] ダークモード以外のテーマ選択

### CI/CD
- [ ] GitHub Actions 公式 Action 化 (`shingan/action@v1`)
- [ ] GitLab CI サンプル追加
- [ ] Fastlane plugin化
- [ ] JIRA / Slack webhook 通知

### API
- [ ] `POST /api/suppressions` — false positive 抑制
- [ ] `POST /api/baselines/{app_id}` — アプリごとのbaseline固定
- [ ] OpenAPI ドキュメント整備

---

## v0.4 — 動的解析連携 (TODO)

> 静的シグナルだけでは「保護の指標があるか」しか分からない。  
> 保護が**実際に有効か**を確認するには動的解析が必要。

- [ ] **Frida スクリプト連携**: SSL pinning bypass 試行 → bypass可否を報告
- [ ] **objection 連携**: jailbreak detection bypass 試行
- [ ] **PT_DENY_ATTACH 有効性確認**: LLDB attach 試行 → detach結果を記録
- [ ] **実機/Simulator 実行モード**: `shingan scan --dynamic --device <udid>`
- [ ] 静的+動的の統合スコアリング

---

## v1.0 — プロダクション対応

- [ ] マルチユーザー対応 (認証 / team workspace)
- [ ] SQLite / PostgreSQL ストレージ移行
- [ ] カスタムYAMLルール対応 (ユーザー定義チェック)
- [ ] MASVS/MASTG チェックリストへの完全マッピング
- [ ] レポートの日本語/英語切り替え
- [ ] Docker イメージ / Homebrew formula

---

## 技術的な差別化方針

| 商用製品の強み | OSSの強み | shingan が狙う中間 |
|---|---|---|
| 広いカバレッジ | 透明性・検証容易性 | **mobile-native の使いやすさ + OSS的な可観測性** |
| CI統合 | カスタマイズ性 | **説明可能なルール + diff管理** |
| ブラックボックス | 要セットアップ | **IPAを放り込めばすぐ結果** |

> 最大の差別化: **「前回から何が増えたか」を明快に出す diff 機能**  
> 既知の問題はbaselineに残し、新規検出のみCIをfailにする運用をサポートする。
