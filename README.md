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
   - Trivy 見 https://trivy.dev
   - Gitleaks 見 https://github.com/gitleaks/gitleaks
   - Grype 見 https://github.com/anchore/grype
   - TruffleHog 見 https://github.com/trufflesecurity/trufflehog
   - Nuclei 見 https://github.com/projectdiscovery/nuclei
   - Nmap 見 https://nmap.org
2. **managed 下載** `vigila engine install <name>` 下載官方 binary 到 `~/.vigila/engines/` 免污染系統 PATH
   - 支援 gitleaks grype trivy trufflehog nuclei
3. **docker 容器** 本機沒裝時 以容器執行 免在主機裝任何東西
   - 在專案目錄放 `.env` 勾選引擎 `echo "COMPOSE_PROFILES=semgrep,trivy" > .env`
   - 掃描時 vigila 自動以 `docker compose run` 同路徑掛載目標執行 見 `docker-compose.yml`
   - 目前支援 semgrep trivy grype trufflehog

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

# 啟動網頁 http://localhost:7780
vigila serve

# 匯出報告
vigila report <scan-id> -f html -o report.html

# 匯出 SBOM CycloneDX JSON 供 CI 上傳或給下游工具
vigila sbom export <scan-id> -o sbom.json

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
| Secret 密鑰 | Gitleaks | 洩漏的 token key 密碼 |
| Secret 驗證 | TruffleHog | 驗證式密鑰 只收已驗證的活密鑰 |
| DAST 動態掃描 | Nuclei | 網頁漏洞 target 為 URL |
| VA 弱點評估 | Nmap | 網路服務偵測 target 為 host 或 IP |

五類引擎互補 SAST 找自己寫的錯 SCA 找用的套件的洞 Secret 找寫死的密鑰 DAST 對運行中的網頁發請求 VA 盤點開放的服務

### 掃描模式

- `--engine <name>` 單一引擎
- `--engine all` 全部適用此目標的引擎
- `--profile <name>` 預定義流程

### 目標型態

每個引擎宣告自己接受的目標型態 vigila 依此決定 `--engine all` 要跑哪些引擎

| 目標型態 | 範例 | 適用引擎 |
|---------|------|---------|
| 路徑 | `./myapp` `/tmp/repo` | semgrep trivy grype gitleaks trufflehog |
| URL | `https://example.com` | nuclei |
| 主機 | `scanme.nmap.org` `10.0.0.1:443` | nmap |

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
| va-only | nmap | 網路服務弱點評估 target 為 host 或 IP |

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

## 授權

[MIT](./LICENSE)

