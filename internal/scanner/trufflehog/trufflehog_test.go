package trufflehog

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* TestParse 解析 NDJSON 確認只收 Verified 且 severity 映射正確 */
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

	/* sample 含 3 行 2 個 Verified true 1 個 Verified false 應只收 2 個 */
	if len(findings) != 2 {
		t.Fatalf("期望 2 個 finding 實際 %d", len(findings))
	}

	/* AWS 已驗證 應為 CRITICAL */
	f1 := findings[0]
	if f1.RuleID != "AWS" {
		t.Errorf("RuleID 應為 AWS 實際 %s", f1.RuleID)
	}
	if f1.Severity != model.SeverityCritical {
		t.Errorf("Verified secret 應為 CRITICAL 實際 %s", f1.Severity)
	}
	if f1.FilePath != "config/aws.conf" {
		t.Errorf("FilePath 應為 config/aws.conf")
	}
	if f1.StartLine == nil || *f1.StartLine != 12 {
		t.Errorf("StartLine 應為 12")
	}
	if f1.SecretType != "AWS" {
		t.Errorf("SecretType 應為 AWS")
	}
	if f1.HashCode == "" {
		t.Error("HashCode 不應為空")
	}

	/* GitHub 已驗證 */
	f2 := findings[1]
	if f2.RuleID != "GitHub" {
		t.Errorf("RuleID 應為 GitHub 實際 %s", f2.RuleID)
	}
	if f2.Severity != model.SeverityCritical {
		t.Errorf("Verified secret 應為 CRITICAL 實際 %s", f2.Severity)
	}
	if f2.FilePath != ".env" {
		t.Errorf("FilePath 應為 .env")
	}
}

/* TestParseEmpty 確認空輸入不出錯 */
func TestParseEmpty(t *testing.T) {
	s := &Scanner{}
	findings, err := s.Parse([]byte(``))
	if err != nil {
		t.Fatalf("Parse 空輸入失敗: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("期望 0 個 finding 實際 %d", len(findings))
	}
}

/* TestExitCodeIsFindings 確認 exit code 判讀 */
func TestExitCodeIsFindings(t *testing.T) {
	s := &Scanner{}
	if s.ExitCodeIsFindings(0) {
		t.Error("exit 0 不應為有發現")
	}
}

/* TestBuildCommand 確認指令含 filesystem 與 --results=verified */
func TestBuildCommand(t *testing.T) {
	s := &Scanner{}
	binary, args := s.BuildCommand("/tmp/repo", scanner.Options{})
	if binary != "trufflehog" {
		t.Error("binary 應為 trufflehog")
	}
	joined := ""
	for _, a := range args {
		joined += a + " "
	}
	if !containsStr(joined, "filesystem") {
		t.Error("應含 filesystem 子命令")
	}
	if !containsStr(joined, "--results=verified") {
		t.Error("應含 --results=verified")
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
