# 貢獻指南

感謝你有興趣為 Vigila 貢獻。本文件說明開發流程與慣例。

## 開發環境

- Go 1.25+
- Node 24+（前端 SPA）
- 掃描引擎 binary（依需求安裝，見 [README](./README.md) 的安裝方式）

```bash
make build    # 編譯前端與 Go binary
make test     # 執行所有測試
make vet      # 靜態檢查
make sqlc     # 重新產生 DB 存取碼
```

## 提交流程

1. 從 `main` 開分支
2. 開發時邊寫邊補單元測試（adapter 的 Parse 以各引擎 sample 輸出作 fixture）
3. 送 PR 前確認以下全綠：
   ```bash
   go vet ./...
   go test -race ./...
   gofmt -s -l .        # 應無輸出
   staticcheck ./...
   ```
4. 送 PR，填寫 PR 範本的測試計畫

## 程式碼慣例

- **格式**：`gofmt -s` 與 `goimports` 為必要，無風格爭論
- **錯誤處理**：一律以 `fmt.Errorf("...: %w", err)` 包裝並帶上下文
- **測試**：標準 `go test` + 表格驅動測試，`-race` 必跑，目標覆蓋率 80%+
- **檔案組織**：多個小檔優於少數大檔，單檔 200–400 行為宜、800 為上限
- **sqlc 檔**：`schema.sql`／`queries.sql` 須純 ASCII（CJK 註解會讓 sqlc generate 解析失敗）

## Commit 訊息

採 [Conventional Commits](https://www.conventionalcommits.org/)，**單行、無 body**：

```
<type>: <描述>
```

型別：`feat`、`fix`、`refactor`、`docs`、`test`、`chore`、`perf`、`ci`

範例：`feat: nmap CVE 偵測與 va-deep profile`

## 新增掃描引擎

每個引擎實作 `scanner.Scanner` 介面，新增引擎只需在 `internal/scanner/<name>/` 加一個 adapter 檔案並在 `cmd/vigila/main.go` 匿名 import。務必附上以真實工具輸出為 fixture 的 `Parse` 測試。

## 回報問題

- **一般 bug／功能**：開 issue，使用對應範本
- **安全漏洞**：請勿開公開 issue，見 [SECURITY.md](./SECURITY.md)
