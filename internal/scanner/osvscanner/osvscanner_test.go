package osvscanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* TestParse 解析 sample JSON 確認 SCA 欄位 CVE 別名與 group max_severity 映射 */
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

	/* flask: CVE 取自 aliases group max_severity 8.7 → HIGH */
	f1 := findings[0]
	if f1.RuleID != "CVE-2023-30861" {
		t.Errorf("RuleID 應取 CVE 別名 CVE-2023-30861 實際 %s", f1.RuleID)
	}
	if f1.PkgName != "flask" || f1.InstalledVersion != "2.0.0" {
		t.Errorf("套件資訊錯誤 %s@%s", f1.PkgName, f1.InstalledVersion)
	}
	if f1.Severity != model.SeverityHigh {
		t.Errorf("max_severity 8.7 應為 HIGH 實際 %s", f1.Severity)
	}
	if f1.CVSSScore == nil || *f1.CVSSScore != 8.7 {
		t.Errorf("CVSSScore 應為 8.7")
	}
	if f1.FilePath != "/tmp/app/requirements.txt" {
		t.Errorf("FilePath 應為 source path 實際 %s", f1.FilePath)
	}
	if f1.Engine != binaryName || f1.Category != model.CategorySCA {
		t.Errorf("engine/category 錯誤 %s %s", f1.Engine, f1.Category)
	}
	if len(f1.References) != 2 {
		t.Errorf("references 應有 2 筆 實際 %d", len(f1.References))
	}
	if f1.HashCode == "" {
		t.Error("HashCode 不應為空")
	}
	/* osv id 保留於 UniqueIDFromTool 供追溯 */
	if !strings.Contains(f1.UniqueIDFromTool, "PYSEC-2023-62") {
		t.Errorf("UniqueIDFromTool 應含 osv id 實際 %s", f1.UniqueIDFromTool)
	}

	/* jinja2: max_severity 5.4 → MEDIUM */
	f2 := findings[1]
	if f2.RuleID != "CVE-2024-22195" {
		t.Errorf("RuleID 應為 CVE-2024-22195 實際 %s", f2.RuleID)
	}
	if f2.Severity != model.SeverityMedium {
		t.Errorf("max_severity 5.4 應為 MEDIUM 實際 %s", f2.Severity)
	}
}

/* TestParseNoCVEAlias 無 CVE 別名時 RuleID 退回 osv id */
func TestParseNoCVEAlias(t *testing.T) {
	raw := []byte(`{"results":[{"source":{"path":"go.mod"},"packages":[{"package":{"name":"x","version":"1.0.0"},"vulnerabilities":[{"id":"GO-2024-1","aliases":["GHSA-aaaa"]}],"groups":[{"ids":["GO-2024-1"],"max_severity":"9.8"}]}]}]}`)
	s := &Scanner{}
	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse 失敗: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("期望 1 個 finding 實際 %d", len(findings))
	}
	if findings[0].RuleID != "GO-2024-1" {
		t.Errorf("無 CVE 別名應退回 osv id 實際 %s", findings[0].RuleID)
	}
	if findings[0].Severity != model.SeverityCritical {
		t.Errorf("max_severity 9.8 應為 CRITICAL 實際 %s", findings[0].Severity)
	}
}

/* TestParseEmpty 空 results 不出錯 */
func TestParseEmpty(t *testing.T) {
	s := &Scanner{}
	findings, err := s.Parse([]byte(`{"results":[]}`))
	if err != nil {
		t.Fatalf("Parse 空 JSON 失敗: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("期望 0 個 finding 實際 %d", len(findings))
	}
}

/* TestExitCodeIsFindings osv-scanner exit 1 代表有發現 */
func TestExitCodeIsFindings(t *testing.T) {
	s := &Scanner{}
	if !s.ExitCodeIsFindings(1) {
		t.Error("exit 1 應為有發現")
	}
	if s.ExitCodeIsFindings(0) {
		t.Error("exit 0 不應為有發現")
	}
	if s.ExitCodeIsFindings(127) {
		t.Error("exit 127 為真正錯誤 不應視為發現")
	}
}

/* TestBuildCommand 指令含 scan --format json 與目標 */
func TestBuildCommand(t *testing.T) {
	s := &Scanner{}
	binary, args := s.BuildCommand("/tmp/repo", scanner.Options{})
	if binary != "osv-scanner" {
		t.Errorf("binary 應為 osv-scanner 實際 %s", binary)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "scan") || !strings.Contains(joined, "--format json") {
		t.Errorf("指令應含 scan --format json 實際 %s", joined)
	}
	if !strings.Contains(joined, "/tmp/repo") {
		t.Errorf("指令應含目標路徑 實際 %s", joined)
	}
}
