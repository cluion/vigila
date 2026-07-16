# Vigila

> **Vigila** 拉丁文「我監視 守護」 開源資安掃描編排平台

單一 Go binary 同時是 **CLI 工具** 與 **Web 平台** 整合 SAST / SCA / Secret 等掃描引擎 支援單一掃描或一套流程 profile 編排 最後產出標準化報告 **CLI 掃描的結果會寫入同一個資料庫 打開網頁即可檢視**

## 快速開始

### 安裝

```bash
git clone https://github.com/cluion/vigila.git
cd vigila
make build
./bin/vigila version
```

需先安裝掃描引擎 其中之一或多個
- Semgrep `pip install semgrep` 或見 https://semgrep.dev
- Trivy 見 https://trivy.dev
- Gitleaks 見 https://github.com/gitleaks/gitleaks

### 使用

```bash
# 單一引擎掃描
vigila scan ./myapp --engine semgrep

# 全引擎掃描
vigila scan ./myapp --engine all

# profile 流程掃描
vigila scan ./myapp --profile code-audit

# 啟動網頁 http://localhost:7780
vigila serve

# 匯出報告
vigila report <scan-id> -f html -o report.html
```

## 功能

### 掃描引擎

| 類別 | 引擎 | 掃描目標 |
|------|------|---------|
| SAST 原碼掃描 | Semgrep | 程式碼安全缺陷 SQLi Cmdi XSS 等 |
| SCA 依賴容器 | Trivy | 套件漏洞 CVE 容器 IaC |
| Secret 密鑰 | Gitleaks | 洩漏的 token key 密碼 |

三引擎互補 SAST 找自己寫的錯 SCA 找用的套件的洞 Secret 找寫死的密鑰

### 掃描模式

- `--engine <name>` 單一引擎
- `--engine all` 全部已註冊引擎
- `--profile <name>` 預定義流程

內建 profile

| profile | 引擎 | 用途 |
|---------|------|------|
| sast-only | semgrep | 僅原碼掃描 |
| sca-only | trivy | 僅依賴掃描 |
| secret-only | gitleaks | 僅密鑰掃描 |
| code-audit | semgrep + gitleaks | 程式碼資安審計 |
| full | semgrep + trivy + gitleaks | 全引擎完整掃描 |

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
- **前端** React 19 Vite 8 TypeScript 6
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

