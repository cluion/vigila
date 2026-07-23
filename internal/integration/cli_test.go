//go:build integration

package integration

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cluion/vigila/internal/cli"
)

/*
	TestScanCommandEndToEnd 實跑 scan cobra 命令 掃植入密鑰的目錄

涵蓋 cli 的 RunE 閉包（store 開啟、orchestrator 呼叫、printSummary）——單元測不到的路徑
以 XDG_DATA_HOME 導向暫存目錄 避免寫入真實使用者 DB
*/
func TestScanCommandEndToEnd(t *testing.T) {
	requireEngine(t, "gitleaks")

	t.Setenv("XDG_DATA_HOME", t.TempDir())

	dir := t.TempDir()
	secret := "-----BEGIN RSA PRIVATE KEY-----\n" +
		"MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF0qN6t1kv7EXAMPLEKEYDATA1234\n" +
		"-----END RSA PRIVATE KEY-----\n"
	if err := os.WriteFile(filepath.Join(dir, "leaked.pem"), []byte(secret), 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := cli.NewScanCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{dir, "--engine", "gitleaks"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("scan 命令執行失敗: %v\n輸出:\n%s", err, buf.String())
	}

	out := buf.String()
	if !strings.Contains(out, "掃描完成") {
		t.Errorf("輸出應含掃描完成摘要 實際:\n%s", out)
	}
	if strings.Contains(out, "發現: 0 個") {
		t.Errorf("應偵測到植入密鑰 但回報 0 個 實際:\n%s", out)
	}
}
