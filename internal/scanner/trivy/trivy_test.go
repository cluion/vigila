package trivy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* TestParse 解析 sample JSON 確認 CVE 套件 CVSS 映射正確 */
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

	/* 第一個 HIGH lodash CVE */
	f1 := findings[0]
	if f1.RuleID != "CVE-2024-12345" {
		t.Errorf("RuleID 應為 CVE-2024-12345 實際 %s", f1.RuleID)
	}
	if f1.Severity != model.SeverityHigh {
		t.Errorf("HIGH 應保留 實際 %s", f1.Severity)
	}
	if f1.PkgName != "lodash" {
		t.Errorf("PkgName 應為 lodash")
	}
	if f1.FixedVersion != "4.17.21" {
		t.Errorf("FixedVersion 應為 4.17.21")
	}
	if f1.CVSSScore == nil || *f1.CVSSScore != 7.5 {
		t.Errorf("CVSSScore 應為 7.5")
	}
	if f1.CWE != "CWE-787" {
		t.Errorf("CWE 應為 CWE-787")
	}
	if f1.UniqueIDFromTool != "CVE-2024-12345" {
		t.Errorf("UniqueIDFromTool 應為 CVE")
	}
	if f1.HashCode == "" {
		t.Error("HashCode 不應為空")
	}

	/* 第二個 MEDIUM requests */
	f2 := findings[1]
	if f2.Severity != model.SeverityMedium {
		t.Errorf("MEDIUM 應保留 實際 %s", f2.Severity)
	}
	if f2.PkgName != "requests" {
		t.Errorf("PkgName 應為 requests")
	}
}

/* TestParseEmptyVulns 確認 Vulnerabilities 為 null 的 target 不出錯 */
func TestParseEmptyVulns(t *testing.T) {
	raw := []byte(`{"Results":[{"Target":"a.txt","Vulnerabilities":null}]}`)
	s := &Scanner{}
	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse null vulns 失敗: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("期望 0 個 finding 實際 %d", len(findings))
	}
}

/* TestExitCodeIsFindings 恆為 false 因用 --exit-code 0 */
func TestExitCodeIsFindings(t *testing.T) {
	s := &Scanner{}
	if s.ExitCodeIsFindings(0) || s.ExitCodeIsFindings(1) {
		t.Error("trivy 用 --exit-code 0 不應視 finding 為非 0")
	}
}

/* TestBuildCommand 確認指令含 --exit-code 0 */
func TestBuildCommand(t *testing.T) {
	s := &Scanner{}
	binary, args := s.BuildCommand("/tmp/repo", scanner.Options{})
	if binary != "trivy" {
		t.Error("binary 應為 trivy")
	}
	joined := ""
	for _, a := range args {
		joined += a + " "
	}
	if !contains(joined, "--exit-code 0") {
		t.Error("應含 --exit-code 0")
	}
	if !contains(joined, "--scanners vuln") {
		t.Error("應含 --scanners vuln")
	}
}

/* TestBuildCommandExclude 排除清單應轉為 --skip-dirs 旗標 */
func TestBuildCommandExclude(t *testing.T) {
	s := &Scanner{}
	_, args := s.BuildCommand("/tmp/repo", scanner.Options{Exclude: []string{"vendor", "testdata"}})
	joined := ""
	for _, a := range args {
		joined += a + " "
	}
	if !contains(joined, "--skip-dirs vendor") || !contains(joined, "--skip-dirs testdata") {
		t.Errorf("應含兩個 --skip-dirs 實際 %s", joined)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 ||
		(len(s) > 0 && len(sub) > 0 && indexOf(s, sub) >= 0))
}

func indexOf(s, sub string) int {
	for i := 0; i <= len(s)-len(sub); i++ {
		match := true
		for j := 0; j < len(sub); j++ {
			if s[i+j] != sub[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
