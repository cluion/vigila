//go:build integration

package integration

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cluion/vigila/internal/scanner"
)

/* repoRoot 由本測試檔位置回推專案根目錄（docker compose 需在此找 docker-compose.yml） */
func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("無法取得測試檔路徑")
	}
	/* internal/integration/docker_test.go → 上溯兩層為 repo root */
	root := filepath.Join(filepath.Dir(file), "..", "..")
	abs, err := filepath.Abs(root)
	if err != nil {
		t.Fatalf("解析 repo root 失敗: %v", err)
	}
	if _, err := os.Stat(filepath.Join(abs, "docker-compose.yml")); err != nil {
		t.Fatalf("repo root %s 找不到 docker-compose.yml: %v", abs, err)
	}
	return abs
}

/*
	TestGitleaksDockerEndToEnd 走 docker profile 掃植入密鑰的目錄 驗證 runDocker 路徑

單元測試碰不到的 runDocker（docker compose run + 掛載 + 報告讀回）。前置：
  - 清空 VIGILA_ENGINES_DIR → 無 managed binary，來源解析退到 docker
  - COMPOSE_PROFILES=gitleaks → 啟用 docker profile（env 優先於 .env）
  - chdir 至 repo root → docker compose 找得到 docker-compose.yml
*/
func TestGitleaksDockerEndToEnd(t *testing.T) {
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker 不可用 略過 docker profile 整合測試")
	}

	/* 強制走 docker：managed 目錄清空、啟用 profile、切到 repo root */
	t.Setenv("VIGILA_ENGINES_DIR", t.TempDir())
	t.Setenv("COMPOSE_PROFILES", "gitleaks")
	t.Chdir(repoRoot(t))

	/* 確認來源真的解析為 docker 否則測的不是 runDocker */
	if src := scanner.ResolveSourceFor("gitleaks", "gitleaks"); src != scanner.SourceDocker {
		t.Fatalf("gitleaks 來源應為 docker 實際 %v（前置未生效）", src)
	}

	orch, q := newOrchestrator(t)
	gl, err := scanner.Get("gitleaks")
	if err != nil {
		t.Fatalf("取得 gitleaks 引擎失敗: %v", err)
	}

	dir := t.TempDir()
	secret := "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF0qN6t1kv7EXAMPLEKEYDATA1234\n" +
		"-----END RSA PRIVATE KEY-----\n"
	if err := os.WriteFile(filepath.Join(dir, "leaked.pem"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := orch.RunSingle(context.Background(), gl, dir, scanner.Options{})
	if err != nil {
		t.Fatalf("gitleaks docker 掃描失敗: %v", err)
	}
	if res.Total == 0 {
		t.Fatalf("docker 路徑應偵測到植入密鑰 實際 0（skipped=%v）", res.Skipped)
	}

	n, err := q.CountFindingsByScan(context.Background(), res.ScanID)
	if err != nil {
		t.Fatalf("查詢 scan findings 失敗: %v", err)
	}
	if n == 0 {
		t.Error("docker 掃描的 findings 應寫入 DB")
	}
}
