# Changelog

本專案所有重要變更皆記錄於此。

格式依循 [Keep a Changelog](https://keepachangelog.com/zh-TW/1.1.0/)，版本號採 [語意化版本](https://semver.org/lang/zh-TW/)。

## [Unreleased]

### Security
- 升級間接依賴 `google.golang.org/grpc` v1.82.0 → v1.82.1，消除 Dependabot high 警告（gRPC-Go xDS RBAC / HTTP/2）；經 sigstore-go 帶入，govulncheck 本就顯示未觸及漏洞路徑，屬預防性升級

## [0.26.0] - 2026-07-24

### Added
- **整合測試 CI job**（build tag `integration`）：涵蓋單元測試碰不到的 subprocess/e2e 路徑——adapter `Run()`、cli `scan` 命令的 RunE、core 掃描執行。CI 以 vigila 自身 managed install 取得引擎（同時 e2e 驗證 installer），對植入密鑰的目錄跑 gitleaks 端到端並驗證 findings 寫入 DB

### Tests
- 新增 `internal/integration` 套件：gitleaks 端到端掃描（Run + core + DB）、乾淨目錄零誤報、`scan` cobra 命令 e2e

## [0.25.0] - 2026-07-23

### Added
- **nmap CVE 偵測**：nmap 掃描加 `--script vuln` 跑 NSE 弱點腳本，vulners 的結構化 CVE 表格逐一成 finding（severity 取 CVSS），其他腳本每支一筆（含 VULNERABLE 為 HIGH）——nmap 從服務盤點升級為真弱點掃描
- **`va-deep` 內建 profile**：nmap + openvas 串接，服務盤點加完整弱點掃描（需先起 openvas 容器）
- **CONTRIBUTING / SECURITY / CODE_OF_CONDUCT** 與 issue／PR 範本，補齊社群協作文件

### Tests
- **API 契約測試**：鎖定 scans／findings／engines／stats／profiles 端點回應的核心 JSON 欄位與 envelope，防破壞性 wire format 變更
- 大幅補強單元測試覆蓋率：scanner 基礎（DefaultRun／registry／docker 參數）、各引擎 metadata、api handlers 與 SSE／SPA、core profile 與 helper、store 開啟路徑、engine 純函式

## [0.24.0] - 2026-07-23

### Fixed
- **openvas**：GMP 呼叫改以 `docker compose exec --user gvm` 執行——gvm-tools 明確拒絕以 root 執行，而 exec 預設為 root，先前無法在真環境運作（本機實跑 immauss/openvas 掃描發現並修正，補真實 get_reports XML 的 regression fixture）

### Docs
- 記錄 openvas host 網路的埠衝突陷阱：主機 6379/5432 被佔用會使容器內 redis 啟動失敗、GVM 卡初始化

## [0.23.0] - 2026-07-23

### Added
- `web-deep` 內建 profile：一次跑全 DAST 引擎（nuclei + nikto + sqlmap + zap）做網頁深度掃描，不 FailFast

### Tests
- nikto、sqlmap 補真實工具輸出的 regression fixture（以本機故意含漏洞的容器 smoke test 驗證解析）
- 新增 profile 測試：web-deep 引擎組合、ProfileNames 涵蓋、所有內建 profile 引擎名皆可解析

## [0.22.0] - 2026-07-22

### Added
- **P6 全類型擴充完成**（13 引擎 6 類）：
  - **nikto**（DAST 伺服器掃描）：對網頁伺服器偵測已知漏洞與設定缺陷，JSON 報告寫檔讀回
  - **sqlmap**（DAST 注入偵測）：解析 stdout 注入點區塊，Run 前綴 `vigila-target` 標記取回 URL，docker 用 Parrot 維護的 `parrotsec/sqlmap`
  - **openvas/GVM**（VA，docker-only）：以 `docker compose exec` 呼叫容器內 gvm-cli 走 GMP 協定，建 target/task、輪詢完成後取報告 XML；`gmp` 介面抽象化便於測試

## [0.21.0] - 2026-07-22

### Added
- **供應鏈版本釘選**（C6 補完）：`engine install <name>@<version>` 釘選特定版本，走 GitHub tag 端點並記錄於 `~/.vigila/engines/engines.lock.json`（版本／sha256／簽章狀態／釘選旗標）
- 純 `install <name>` 沿用既有釘選版本，`<name>@latest` 抓最新並解除釘選
- API install 接受可選 `{"version"}`，engines 清單回 `pinned_version`，前端面板版本欄顯示釘選標記

## [0.20.0] - 2026-07-21

### Added
- **cosign keyless 簽章驗證**（C6）：managed install 以 `sigstore-go` 對有簽章的引擎（trivy／grype／syft／trufflehog）驗證來源真實性——trivy 走 `.sigstore.json` bundle，其餘走分離式 `.sig`+`.pem`，含 SAN/OIDC 身分釘選、TUF 信任根
- CLI／API／前端面板皆呈現簽章狀態

### Security
- 未發佈簽章的引擎（gitleaks／nuclei／osv-scanner）維持 checksum-only 並明確警告無法驗證來源真實性

## [0.19.1] - 2026-07-21

### Fixed
- CI 修綠：gofmt-s 格式、staticcheck 死碼與自比對、gosec 檔案權限收斂與日誌跳脫
- **A5(a) 專案身分模型重建**（migration 005）：新增 `target_key`（正規化絕對路徑／URL host）為唯一身分鍵，`name` 降為可重複顯示標籤，FK-off 安全重建保住 scans/findings，修不同路徑同名目錄混淆
- 趨勢圖選單顯示路徑以區分同名專案

## [0.19.0] - 2026-07-20

### Fixed
- **品質打磨輪**（四代理稽核後分群修復）：
  - 前端可用性：嚴重度篩選、掃描啟動失敗提示、可關閉錯誤橫幅、長路徑捲動、卡片鍵盤可及、狀態中文化
  - 核心資料正確性：per-scan 清單／計數／報告／trends 改走 `scan_findings`、未裝引擎記 skipped 不使整場失敗、upsert 以 COALESCE 刷新 fixed_version/cvss、Grype Negligible→LOW、DAST fingerprint 納入 method

### Security
- `ValidateTarget` 防引數走私（對齊 exclude）
- gitleaks 系統模式明文報告改寫 0700 暫存目錄
- 可選 token 認證（`serve --auth-token`／`VIGILA_AUTH_TOKEN`，Bearer 或 `?token=`，constant-time）與每 IP 權杖桶限流
- serve 啟動回收殘留 running 掃描、SBOM diff 脫敏

## [0.14.0 – 0.18.0] - 2026-07-18 – 2026-07-20

### Added
- 引擎面板 Docker 開關、docker 10/10 全引擎覆蓋、面板一鍵安裝
- 網頁多選引擎、掃描排除路徑、上傳壓縮包掃描
- SBOM 多格式匯出、report 套件測試補強

## [0.13.0] - 2026-07-18

### Added
- SBOM diff（供應鏈漂移偵測）
- osv-scanner（SCA，裸 binary managed 安裝）、checkov（IaC 新類別）、OWASP ZAP（DAST）

### Security
- CI 加 staticcheck／govulncheck／gosec + 檔案權限硬化

## [0.7.0 – 0.12.1] - 2026-07-17 – 2026-07-18

### Added
- 引擎面板頁 + 導航、engine install spec 表、VERSION + SOURCE 欄位
- docker 來源（動態掛載）、managed install 下載
- SBOM 產生／檢視／匯出／獨立命令

### Fixed
- 多輪 code review 修正

## [0.6.0] - 2026-07-17

### Added
- DAST/VA 引擎：Nuclei（DAST）、Nmap（VA）
- Finding model 擴充 url/host/port/method、migration 003、DAST/VA fingerprint 公式

## [0.5.0] - 2026-07-17

### Added
- SCA/Secret 引擎補充：Grype（SCA 互補）、TruffleHog（驗證式 secret）

## [0.4.0] - 2026-07-17

### Added
- 前端升級 Tailwind v4 + shadcn/ui
- 歷史趨勢圖（後端 trends API）、一鍵重掃、command palette（cmdk）、暗亮色主題切換

## [0.3.0] - 2026-07-16

### Added
- diff web 視圖、CI workflow（push/PR 測試）、發版測試關卡

### Changed
- gofmt 全庫統一

## [0.2.0] - 2026-07-16

### Added
- 漏洞狀態管理、掃描 diff（CLI + API + migration 002）
- FailFast 與 exit code 判斷

### Fixed
- 掃描語意修正（trigger_source/scan_type/stats 維度）

## [0.1.0] - 2026-07-16

### Added
- MVP：三引擎（Semgrep/Trivy/Gitleaks）、CLI + Web、profile 流程、SSE、報告匯出（SARIF/JSON/HTML）

[Unreleased]: https://github.com/cluion/vigila/compare/v0.26.0...HEAD
[0.26.0]: https://github.com/cluion/vigila/compare/v0.25.0...v0.26.0
[0.25.0]: https://github.com/cluion/vigila/compare/v0.24.0...v0.25.0
[0.24.0]: https://github.com/cluion/vigila/compare/v0.23.0...v0.24.0
[0.23.0]: https://github.com/cluion/vigila/compare/v0.22.0...v0.23.0
[0.22.0]: https://github.com/cluion/vigila/compare/v0.21.0...v0.22.0
[0.21.0]: https://github.com/cluion/vigila/compare/v0.20.0...v0.21.0
[0.20.0]: https://github.com/cluion/vigila/compare/v0.19.1...v0.20.0
[0.19.1]: https://github.com/cluion/vigila/compare/v0.19.0...v0.19.1
[0.19.0]: https://github.com/cluion/vigila/compare/v0.13.0...v0.19.0
[0.13.0]: https://github.com/cluion/vigila/compare/v0.6.0...v0.13.0
[0.6.0]: https://github.com/cluion/vigila/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/cluion/vigila/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/cluion/vigila/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/cluion/vigila/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/cluion/vigila/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/cluion/vigila/releases/tag/v0.1.0
