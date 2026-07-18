package checkov

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* TestParse 解析單一 check_type 物件形式 確認 IaC 欄位與 severity 預設 */
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

	/* 第一筆 severity null → 預設 MEDIUM 行號取 file_line_range */
	f1 := findings[0]
	if f1.RuleID != "CKV_AWS_260" {
		t.Errorf("RuleID 應為 CKV_AWS_260 實際 %s", f1.RuleID)
	}
	if f1.Engine != binaryName || f1.Category != model.CategoryIaC {
		t.Errorf("engine/category 錯誤 %s %s", f1.Engine, f1.Category)
	}
	if f1.Severity != model.SeverityMedium {
		t.Errorf("severity null 應預設 MEDIUM 實際 %s", f1.Severity)
	}
	if f1.FilePath != "/main.tf" {
		t.Errorf("FilePath 應為 /main.tf 實際 %s", f1.FilePath)
	}
	if f1.StartLine == nil || *f1.StartLine != 5 || f1.EndLine == nil || *f1.EndLine != 12 {
		t.Errorf("行號範圍應為 5-12")
	}
	if len(f1.References) != 1 {
		t.Errorf("guideline 應成為 1 筆 reference 實際 %d", len(f1.References))
	}
	if !strings.Contains(f1.UniqueIDFromTool, "aws_security_group.sg") {
		t.Errorf("UniqueIDFromTool 應含 resource 實際 %s", f1.UniqueIDFromTool)
	}
	if f1.HashCode == "" {
		t.Error("HashCode 不應為空")
	}

	/* 第二筆有明確 severity HIGH */
	if findings[1].Severity != model.SeverityHigh {
		t.Errorf("第二筆應為 HIGH 實際 %s", findings[1].Severity)
	}
}

/*
	TestParseArrayForm checkov 掃多框架時頂層為陣列 每個元素一個 check_type

須攤平所有元素的 failed_checks
*/
func TestParseArrayForm(t *testing.T) {
	raw := []byte(`[
	  {"check_type":"terraform","results":{"failed_checks":[
	    {"check_id":"CKV_AWS_1","check_name":"tf issue","file_path":"/a.tf","file_line_range":[1,2]}
	  ]}},
	  {"check_type":"dockerfile","results":{"failed_checks":[
	    {"check_id":"CKV_DOCKER_2","check_name":"docker issue","file_path":"/Dockerfile","file_line_range":[3,3]}
	  ]}}
	]`)

	s := &Scanner{}
	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse 陣列形式失敗: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("兩個框架各一筆 應攤平為 2 實際 %d", len(findings))
	}
	if findings[0].RuleID != "CKV_AWS_1" || findings[1].RuleID != "CKV_DOCKER_2" {
		t.Errorf("攤平順序或內容錯誤 %+v", findings)
	}
}

/* TestParseEmpty 無 failed_checks 不出錯 */
func TestParseEmpty(t *testing.T) {
	s := &Scanner{}
	findings, err := s.Parse([]byte(`{"check_type":"terraform","results":{"failed_checks":[]}}`))
	if err != nil {
		t.Fatalf("Parse 空 JSON 失敗: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("期望 0 個 finding 實際 %d", len(findings))
	}
}

/* TestExitCodeIsFindings checkov exit 1 代表有失敗檢查 */
func TestExitCodeIsFindings(t *testing.T) {
	s := &Scanner{}
	if !s.ExitCodeIsFindings(1) {
		t.Error("exit 1 應為有發現")
	}
	if s.ExitCodeIsFindings(0) {
		t.Error("exit 0 不應為有發現")
	}
}

/* TestBuildCommand 指令含 -d 目標 與 -o json */
func TestBuildCommand(t *testing.T) {
	s := &Scanner{}
	binary, args := s.BuildCommand("/tmp/iac", scanner.Options{})
	if binary != "checkov" {
		t.Errorf("binary 應為 checkov 實際 %s", binary)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-d /tmp/iac") || !strings.Contains(joined, "-o json") {
		t.Errorf("指令應含 -d 目標 與 -o json 實際 %s", joined)
	}
}
