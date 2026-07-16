package gitleaks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* TestParse 解析 sample JSON 確認 secret 欄位與 severity 映射正確 */
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

	/* AWS token 應映射為 CRITICAL */
	f1 := findings[0]
	if f1.RuleID != "aws-access-token" {
		t.Errorf("RuleID 應為 aws-access-token")
	}
	if f1.Severity != model.SeverityCritical {
		t.Errorf("aws token 應為 CRITICAL 實際 %s", f1.Severity)
	}
	if f1.FilePath != "config/aws.conf" {
		t.Errorf("FilePath 不符")
	}
	if f1.StartLine == nil || *f1.StartLine != 5 {
		t.Errorf("StartLine 應為 5")
	}
	if f1.UniqueIDFromTool != "config/aws.conf:aws-access-token:5" {
		t.Errorf("UniqueIDFromTool 應為 Fingerprint 值")
	}
	if f1.HashCode == "" {
		t.Error("HashCode 不應為空")
	}

	/* GitHub PAT 應映射為 CRITICAL */
	f2 := findings[1]
	if f2.Severity != model.SeverityCritical {
		t.Errorf("github-pat 應為 CRITICAL 實際 %s", f2.Severity)
	}
}

/* TestParseEmpty 確認空 array 不出錯 */
func TestParseEmpty(t *testing.T) {
	s := &Scanner{}
	findings, err := s.Parse([]byte(`[]`))
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
}

/* TestMapSeverity 確認 severity 映射邏輯 */
func TestMapSeverity(t *testing.T) {
	tests := []struct {
		rule string
		want model.Severity
	}{
		{"aws-access-token", model.SeverityCritical},
		{"github-pat", model.SeverityCritical},
		{"private-key", model.SeverityCritical},
		{"generic-api-key", model.SeverityHigh},
		{"some-other-rule", model.SeverityHigh},
	}
	for _, tt := range tests {
		got := mapSeverity(tt.rule)
		if got != tt.want {
			t.Errorf("mapSeverity(%s) = %s 想要 %s", tt.rule, got, tt.want)
		}
	}
}

/* TestMaskSecret 確認 secret 遮蔽 */
func TestMaskSecret(t *testing.T) {
	short := maskSecret("abc")
	if short != "****REDACTED****" {
		t.Errorf("短字串應全遮蔽")
	}
	long := maskSecret("AKIA1234567890ABCDEF")
	if long == "AKIA1234567890ABCDEF" {
		t.Errorf("長字串應被遮蔽")
	}
	if len(long) < 10 {
		t.Errorf("遮蔽後長度異常")
	}
}

/* TestBuildCommand 確認指令含 git 與 report-path */
func TestBuildCommand(t *testing.T) {
	s := &Scanner{}
	binary, args := s.BuildCommand("/tmp/repo", scanner.Options{})
	if binary != "gitleaks" {
		t.Error("binary 應為 gitleaks")
	}
	joined := ""
	for _, a := range args {
		joined += a + " "
	}
	if !containsStr(joined, "dir") {
		t.Error("應含 dir 子命令")
	}
	if !containsStr(joined, "--report-format json") {
		t.Error("應含 --report-format json")
	}
}

func containsStr(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if s[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
