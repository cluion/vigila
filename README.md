# Vigila

> **Vigila** 拉丁文「我監視 守護」 開源資安掃描編排平台

單一 Go binary 同時是 **CLI 工具** 與 **Web 平台** 整合 SAST / SCA / Secret 等掃描引擎 支援單一掃描或一套流程 profile 編排 最後產出標準化報告 **CLI 掃描的結果會寫入同一個資料庫 打開網頁即可檢視**

## 快速開始

### 安裝

```bash
# 從原始碼編譯 需 Go 1.25+
git clone https://github.com/cluion/vigila.git
cd vigila
make build
./bin/vigila version
```

### 使用

```bash
# 掃描 偵測本機已安裝的引擎
vigila scan ./myapp --engine semgrep

# 啟動本機網頁 http://localhost:7780
vigila serve

# 檢視引擎狀態
vigila engine list
```

### 用 Docker 啟用掃描引擎

Vigila 本體是 Go binary 不需要 Docker

Docker 只用來勾選啟用掃描引擎

```bash
vigila init                                    # 產生 docker-compose.yml 與 workspace
echo "COMPOSE_PROFILES=semgrep,trivy,gitleaks" > .env
docker compose up -d                            # 啟用勾選的引擎容器
vigila scan workspace/myapp --engine all
```

## 引擎涵蓋

| 類別 | MVP 引擎 | 後續擴充 |
|------|---------|---------|
| SAST 原碼掃描 | Semgrep | SonarQube Bandit CodeQL |
| SCA 依賴/容器 | Trivy | Grype Syft |
| Secret 密鑰 | Gitleaks | TruffleHog |
| DAST Web 應用 | — | OWASP ZAP Nuclei Nikto |
| VA 網路/主機 | — | Nmap OpenVAS |

## 技術棧

- **後端** Go 1.25+ cobra sqlc modernc.org/sqlite
- **前端** React 19 Vite 8 Tailwind v4 shadcn/ui
- **報告** SARIF 2.1.0 + JSON/HTML

## 開發

```bash
make help     # 查看所有指令
make build    # 編譯
make test     # 測試
make vet      # 靜態檢查
make sqlc     # 重新產生 DB 存取碼
```

## 授權

[MIT](./LICENSE)
