package grype

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* TestParse 解析 sample JSON 確認 SCA 欄位與 CVSS 映射正確 */
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

	/* lodash 應為 High 有 fix 版本 CVSS 7.5 */
	f1 := findings[0]
	if f1.RuleID != "CVE-2021-23337" {
		t.Errorf("RuleID 應為 CVE-2021-23337 實際 %s", f1.RuleID)
	}
	if f1.Severity != model.SeverityHigh {
		t.Errorf("lodash 應為 HIGH 實際 %s", f1.Severity)
	}
	if f1.PkgName != "lodash" {
		t.Errorf("PkgName 應為 lodash")
	}
	if f1.InstalledVersion != "4.17.20" {
		t.Errorf("InstalledVersion 應為 4.17.20")
	}
	if f1.FixedVersion != "4.17.21" {
		t.Errorf("FixedVersion 應為 4.17.21 實際 %s", f1.FixedVersion)
	}
	if f1.CVSSScore == nil || *f1.CVSSScore != 7.5 {
		t.Errorf("CVSSScore 應為 7.5")
	}
	if f1.HashCode == "" {
		t.Error("HashCode 不應為空")
	}

	/* express 應為 Critical 無 fix */
	f2 := findings[1]
	if f2.RuleID != "CVE-2022-24999" {
		t.Errorf("RuleID 應為 CVE-2022-24999 實際 %s", f2.RuleID)
	}
	if f2.Severity != model.SeverityCritical {
		t.Errorf("express 應為 CRITICAL 實際 %s", f2.Severity)
	}
	if f2.FixedVersion != "" {
		t.Errorf("express 無 fix FixedVersion 應為空 實際 %s", f2.FixedVersion)
	}
}

/* TestParseEmpty 確認空 matches 不出錯 */
func TestParseEmpty(t *testing.T) {
	s := &Scanner{}
	findings, err := s.Parse([]byte(`{"matches":[]}`))
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
	if s.ExitCodeIsFindings(0) {
		t.Error("exit 0 不應為有發現")
	}
	if s.ExitCodeIsFindings(1) {
		t.Error("exit 1 也不應為有發現 grype 預設不以此判讀")
	}
}

/* TestBuildCommand 確認指令含 dir: 與 -o json */
func TestBuildCommand(t *testing.T) {
	s := &Scanner{}
	binary, args := s.BuildCommand("/tmp/repo", scanner.Options{})
	if binary != "grype" {
		t.Error("binary 應為 grype")
	}
	joined := ""
	for _, a := range args {
		joined += a + " "
	}
	if !containsStr(joined, "dir:/tmp/repo") {
		t.Error("應含 dir:/tmp/repo")
	}
	if !containsStr(joined, "-o json") {
		t.Error("應含 -o json")
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
