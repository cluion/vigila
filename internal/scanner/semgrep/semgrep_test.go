package semgrep

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* TestParse 解析 sample JSON 確認欄位映射正確 */
func TestParse(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sample.json"))
	if err != nil {
		t.Fatalf("讀取 sample 失敗: %v", err)
	}

	s := &Scanner{}
	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse 失敗: %v", err)
	}

	if len(findings) != 2 {
		t.Fatalf("期望 2 個 finding 實際 %d", len(findings))
	}

	/* 第一個 finding ERROR 應映射為 HIGH */
	f1 := findings[0]
	if f1.RuleID != "python.lang.security.audit.dangerous-subprocess-use" {
		t.Errorf("RuleID 不符: %s", f1.RuleID)
	}
	if f1.Severity != model.SeverityHigh {
		t.Errorf("ERROR 應映射為 HIGH 實際 %s", f1.Severity)
	}
	if f1.FilePath != "app/server.py" {
		t.Errorf("FilePath 不符: %s", f1.FilePath)
	}
	if f1.StartLine == nil || *f1.StartLine != 42 {
		t.Errorf("StartLine 應為 42")
	}
	if f1.CWE != "CWE-78" {
		t.Errorf("CWE 應為 CWE-78 實際 %s", f1.CWE)
	}
	if f1.HashCode == "" {
		t.Error("HashCode 不應為空 需由 fallback 計算")
	}

	/* 第二個 finding WARNING 應映射為 MEDIUM fingerprint 非空時作 UniqueIDFromTool */
	f2 := findings[1]
	if f2.Severity != model.SeverityMedium {
		t.Errorf("WARNING 應映射為 MEDIUM 實際 %s", f2.Severity)
	}
	if f2.UniqueIDFromTool != "abc123stablefingerprint" {
		t.Errorf("UniqueIDFromTool 不符: %s", f2.UniqueIDFromTool)
	}
}

/* TestParseEmpty 確認空 results 不出錯 */
func TestParseEmpty(t *testing.T) {
	s := &Scanner{}
	findings, err := s.Parse([]byte(`{"results":[],"errors":[]}`))
	if err != nil {
		t.Fatalf("Parse 空 JSON 失敗: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("期望 0 個 finding 實際 %d", len(findings))
	}
}

/* TestExitCodeIsFindings 確認 exit code 判讀 */
func TestExitCodeIsFindings(t *testing.T) {
	s := &Scanner{}
	if !s.ExitCodeIsFindings(1) {
		t.Error("exit 1 應為有發現")
	}
	if s.ExitCodeIsFindings(0) {
		t.Error("exit 0 不應為有發現")
	}
	if s.ExitCodeIsFindings(2) {
		t.Error("exit 2 不應為有發現")
	}
}

/* TestBuildCommand 確認指令組裝 */
func TestBuildCommand(t *testing.T) {
	s := &Scanner{}
	binary, args := s.BuildCommand("/tmp/repo", scanner.Options{})
	if binary != "semgrep" {
		t.Errorf("binary 應為 semgrep")
	}
	if len(args) == 0 {
		t.Fatal("args 不應為空")
	}
	if args[len(args)-1] != "/tmp/repo" {
		t.Error("最後一個 arg 應為 target")
	}
}
