# Vigila

> **Vigila** 拉丁文「我監視 守護」 開源資安掃描編排平台

單一 Go binary 同時是 **CLI 工具** 與 **Web 平台** 整合 SAST / SCA / Secret / DAST / VA 全類型掃描引擎 支援單一掃描或一套流程 profile 編排 最後產出標準化報告 **CLI 掃描的結果會寫入同一個資料庫 打開網頁即可檢視**

## 快速開始

### 安裝

```bash
git clone https://github.com/cluion/vigila.git
cd vigila
make build
./bin/vigila version
```

需先備妥掃描引擎 其中之一或多個 三種來源擇一 vigila 依 **managed > 本機 PATH > docker** 自動選用

1. **本機安裝** 裝在 PATH 上 vigila 直接呼叫最快
   - Semgrep `pip install semgrep` 或見 https://semgrep.dev
   - Checkov `pip install checkov` 或見 https://www.checkov.io
   - Trivy 見 https://trivy.dev
   - Gitleaks 見 https://github.com/gitleaks/gitleaks
   - Grype 見 https://github.com/anchore/grype
   - TruffleHog 見 https://github.com/trufflesecurity/trufflehog
   - Nuclei 見 https://github.com/projectdiscovery/nuclei
   - Nmap 見 https://nmap.org
   - OSV-Scanner 見 https://google.github.io/osv-scanner
   - OWASP ZAP `brew install --cask zap` 或 docker pull ghcr.io/zaproxy/zaproxy:stable
   - Nikto `brew install nikto` 或見 https://github.com/sullo/nikto
   - SQLMap `brew install sqlmap` 或見 https://github.com/sqlmapproject/sqlmap
   - OpenVAS/GVM 僅支援 docker 執行（immauss/openvas 單容器全套）於引擎面板開啟 Docker 開關
2. **managed 下載** `vigila engine install <name>` 下載官方 binary 到 `~/.vigila/engines/` 免污染系統 PATH
   - 支援 gitleaks grype trivy trufflehog nuclei osv-scanner
   - **供應鏈驗證**：除比對官方 checksums 的 sha256（完整性）外，對有發佈 cosign keyless 簽章的引擎（trivy、grype、syft、trufflehog）額外驗證 checksums 檔的簽章與簽署者身分（Sigstore 信任根經 TUF 取得），確認來源真實性；驗證失敗即中止安裝。未發佈簽章者（gitleaks、nuclei、osv-scanner）維持 checksum-only 並提示
   - **版本釘選**：`vigila engine install <name>@<version>` 安裝特定版本並記錄於 `~/.vigila/engines/engines.lock.json`，之後不帶版本重裝會沿用釘選（可重現、釘住已驗證版本）；`<name>@latest` 抓最新版並解除釘選。面板版本欄會顯示釘選標記
3. **docker 容器** 以官方容器執行 免在主機裝任何東西 明確勾選後蓋過偶然在 PATH 的系統版
   - 在網頁引擎面板點 Docker 開關即可勾選 或手動 `echo "COMPOSE_PROFILES=semgrep,trivy" > .env`
   - 掃描時 vigila 自動以 `docker compose run` 執行 路徑型引擎同路徑掛載目標 nuclei/sqlmap 傳 URL 不掛載 gitleaks/ZAP/nikto 掛輸出目錄讀報告 見 `docker-compose.yml`
   - 目前支援 semgrep trivy grype trufflehog osv-scanner checkov zap nuclei gitleaks nmap nikto sqlmap（12 引擎以 `docker compose run` 一次性執行）
   - **openvas** 特殊：為常駐服務 需先 `docker compose --profile openvas up -d` 起服務（首次會同步弱點 feed 約 15 分鐘）vigila 再以 `docker compose exec --user gvm` 呼叫容器內 gvm-cli 走 GMP 協定建 target/task 輪詢完成後取報告。使用 host 網路（僅 Linux Docker/OrbStack 生效）以掃內網主機；若主機 6379/5432 埠已被佔用會使容器內 redis 啟動失敗、GVM 卡在初始化，請先釋放這些埠或用專屬主機

檢視每個引擎目前的版本與來源 `vigila engine list`

### 使用

```bash
# 單一引擎掃描
vigila scan ./myapp --engine semgrep

# 全引擎掃描 依目標型態自動選用適用的引擎
vigila scan ./myapp --engine all              # 路徑 SAST SCA Secret
vigila scan https://example.com --engine all  # URL  DAST
vigila scan scanme.nmap.org --engine all      # 主機 VA

# profile 流程掃描
vigila scan ./myapp --profile code-audit

# 掃描時順帶產生 SBOM 軟體物料清單 需 syft 僅路徑目標
vigila scan ./myapp --engine trivy --sbom

# 只產 SBOM 不跑漏洞引擎
vigila sbom ./myapp

# 啟動網頁 http://localhost:7780
vigila serve

# 對外或多人共用時 啟用存取 token 認證 前端首次存取需輸入 token
vigila serve --addr 0.0.0.0:7780 --auth-token "$(openssl rand -hex 16)"
# 或用環境變數 VIGILA_AUTH_TOKEN

# 匯出報告
vigila report <scan-id> -f html -o report.html

# 匯出 SBOM 供 CI 上傳或給下游工具 預設 CycloneDX JSON 可轉 SPDX 或 syft 格式
vigila sbom export <scan-id> -o sbom.json                    # CycloneDX JSON（預設）
vigila sbom export <scan-id> -f spdx-json -o sbom.spdx.json  # SPDX 2.2 JSON
vigila sbom export <scan-id> -f syft-json -o sbom.syft.json  # syft JSON

# 比較兩次 SBOM 的套件變化 供應鏈漂移 新增/移除/變動/不變
vigila sbom diff <scan-a> <scan-b>

# 比較兩次掃描的漏洞差異 新增/消失/不變
vigila diff <scan-id-1> <scan-id-2>

# 檢視引擎類別 目標型態與安裝狀態
vigila engine list
```

## 功能

### 掃描引擎

| 類別 | 引擎 | 掃描目標 |
|------|------|---------|
| SAST 原碼掃描 | Semgrep | 程式碼安全缺陷 SQLi Cmdi XSS 等 |
| SCA 依賴容器 | Trivy | 套件漏洞 CVE 容器 IaC |
| SCA 互補 | Grype | Anchore DB 套件漏洞 與 Trivy 交叉補漏 |
| SCA 互補 | OSV-Scanner | Google OSV.dev 資料庫 多生態系依賴漏洞 |
| Secret 密鑰 | Gitleaks | 洩漏的 token key 密碼 |
| Secret 驗證 | TruffleHog | 驗證式密鑰 只收已驗證的活密鑰 |
| IaC 設定掃描 | Checkov | Terraform K8s Dockerfile 等錯誤設定 |
| DAST 動態掃描 | Nuclei | 網頁漏洞 target 為 URL |
| DAST 深度掃描 | OWASP ZAP | 主被動網頁掃描 header CSP XSS 等 target 為 URL |
| DAST 伺服器掃描 | Nikto | 網頁伺服器已知漏洞與設定缺陷 target 為 URL |
| DAST 注入偵測 | SQLMap | SQL 注入探測 帶參數 URL target 為 URL |
| VA 弱點評估 | Nmap | 網路服務偵測 + NSE vuln 腳本比對 CVE target 為 host 或 IP |
| VA 弱點掃描 | OpenVAS/GVM | 完整弱點掃描 走 GMP 僅 docker target 為 host 或 IP |

六類引擎互補 SAST 找自己寫的錯 SCA 找用的套件的洞 Secret 找寫死的密鑰 IaC 找基礎設施設定的錯 DAST 對運行中的網頁發請求 VA 盤點開放的服務

### 掃描模式

- `--engine <name>` 單一引擎
- `--engine all` 全部適用此目標的引擎
- `--profile <name>` 預定義流程

### 目標型態

每個引擎宣告自己接受的目標型態 vigila 依此決定 `--engine all` 要跑哪些引擎

| 目標型態 | 範例 | 適用引擎 |
|---------|------|---------|
| 路徑 | `./myapp` `/tmp/repo` | semgrep trivy grype gitleaks trufflehog |
| URL | `https://example.com` | nuclei zap nikto sqlmap |
| 主機 | `scanme.nmap.org` `10.0.0.1:443` | nmap openvas |

型態由目標字串推導 含 scheme 視為 URL 本機存在的路徑視為路徑 可解析為 IP 或網域名視為主機

明確指定不相容的引擎會直接報錯 不會留下註定失敗的掃描紀錄

```bash
$ vigila scan ./myapp --engine nmap
Error: 引擎 nmap 不支援此目標
  目標 ./myapp 判定為 path
  nmap 接受的目標型態: host
```

內建 profile

| profile | 引擎 | 用途 |
|---------|------|------|
| sast-only | semgrep | 僅原碼掃描 |
| sca-only | trivy | 僅依賴掃描 |
| secret-only | gitleaks | 僅密鑰掃描 |
| code-audit | semgrep + gitleaks | 程式碼資安審計 |
| full | semgrep + trivy + gitleaks | 原始碼全類型 SAST SCA Secret |
| dast-only | nuclei | 網頁動態掃描 target 為 URL |
| web-deep | nuclei + nikto + sqlmap + zap | 網頁深度掃描 全 DAST 引擎 target 為 URL 較耗時 |
| va-only | nmap | 網路服務弱點評估 target 為 host 或 IP |
| va-deep | nmap + openvas | 網路深度弱點評估 服務盤點加完整掃描 target 為 host 需先起 openvas 容器 |

### 網頁介面

`vigila serve` 啟動後 http://localhost:7780 提供

- 掃描歷史列表 含嚴重度統計
- 漏洞詳情表格 可篩選 severity 引擎 排序 搜尋
- 引擎執行狀態卡
- 網頁觸發掃描 含 SSE 即時進度

### 報告匯出

```bash
vigila report <scan-id> -f sarif -o report.sarif  # 可上傳 GitHub code scanning
vigila report <scan-id> -f json  -o report.json   # 結構化資料
vigila report <scan-id> -f html  -o report.html   # 可直接瀏覽器開啟
```

## 技術棧

- **後端** Go 1.25+ cobra chi sqlc modernc.org/sqlite
- **前端** React 19 Vite 8 TypeScript 6 Tailwind v4 shadcn/ui
- **報告** SARIF 2.1.0 owenrumney/go-sarif
- **發行** goreleaser 多平台 binary

## 開發

```bash
make help     # 查看所有指令
make build    # 編譯前端與 Go binary
make test     # 測試
make vet      # 靜態檢查
make sqlc     # 重新產生 DB 存取碼
```

## 變更紀錄

各版本變更見 [CHANGELOG.md](./CHANGELOG.md)。

## 授權

[MIT](./LICENSE)

