//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/scanner"
	"github.com/cluion/vigila/internal/store"
	"github.com/cluion/vigila/internal/store/sqlc"

	/* 匿名 import 觸發 adapter 註冊 供 scanner.Get 取得 */
	_ "github.com/cluion/vigila/internal/scanner/gitleaks"
)

/* newOrchestrator 建立掛暫存 SQLite 的 orchestrator 供整合測試 */
func newOrchestrator(t *testing.T) (*core.Orchestrator, *sqlc.Queries) {
	t.Helper()
	db, err := store.Open(context.Background(), store.Config{
		Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "it.db"),
	})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return core.New(sqlc.New(db)), sqlc.New(db)
}

/* requireEngine 取得已註冊引擎 未安裝則跳過（CI 之外的本機可能沒裝） */
func requireEngine(t *testing.T, name string) scanner.Scanner {
	t.Helper()
	s, err := scanner.Get(name)
	if err != nil {
		t.Fatalf("引擎 %s 未註冊: %v", name, err)
	}
	if err := s.CheckInstalled(); err != nil {
		t.Skipf("引擎 %s 未安裝 略過整合測試: %v", name, err)
	}
	return s
}

/*
	TestGitleaksScanEndToEnd 以真實 gitleaks 掃植入密鑰的目錄 驗證整條 scan 路徑

涵蓋 gitleaks adapter Run（subprocess + 報告檔讀回）+ core 掃描執行 + 寫入 DB
*/
func TestGitleaksScanEndToEnd(t *testing.T) {
	orch, q := newOrchestrator(t)
	gl := requireEngine(t, "gitleaks")

	/* 植入一個 gitleaks 預設規則會偵測的私鑰標頭 */
	dir := t.TempDir()
	secret := "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF0qN6t1kv7EXAMPLEKEYDATA1234\n" +
		"-----END RSA PRIVATE KEY-----\n"
	if err := os.WriteFile(filepath.Join(dir, "leaked.pem"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := orch.RunSingle(context.Background(), gl, dir, scanner.Options{})
	if err != nil {
		t.Fatalf("gitleaks 掃描失敗: %v", err)
	}

	if res.Total == 0 {
		t.Fatalf("應偵測到植入的密鑰 實際 0 個 findings（skipped=%v）", res.Skipped)
	}

	/* findings 應真的寫入 DB 而非只在記憶體 */
	n, err := q.CountFindingsByScan(context.Background(), res.ScanID)
	if err != nil {
		t.Fatalf("查詢 scan findings 失敗: %v", err)
	}
	if n == 0 {
		t.Error("findings 應寫入 DB scan_findings")
	}
}

/*
	TestGitleaksCleanDir 掃無密鑰的目錄應零 findings 不誤報

驗證 gitleaks Run 對乾淨輸入的行為與空結果解析
*/
func TestGitleaksCleanDir(t *testing.T) {
	orch, _ := newOrchestrator(t)
	gl := requireEngine(t, "gitleaks")

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readme.txt"), []byte("hello world 無密鑰"), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := orch.RunSingle(context.Background(), gl, dir, scanner.Options{})
	if err != nil {
		t.Fatalf("掃描乾淨目錄失敗: %v", err)
	}
	if res.Total != 0 {
		t.Errorf("乾淨目錄不應有 findings 實際 %d", res.Total)
	}
}
