package report

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/cluion/vigila/internal/store/sqlc"
)

/* strPtr / intPtr 為測試用指標輔助函式 避免重複 */
func strPtr(s string) *string { return &s }
func intPtr(i int64) *int64   { return &i }

/* TestBuildReportDataSummary 驗證 severity 統計計數正確 */
func TestBuildReportDataSummary(t *testing.T) {
	findings := []sqlc.Finding{
		{Severity: "CRITICAL"},
		{Severity: "CRITICAL"},
		{Severity: "HIGH"},
		{Severity: "MEDIUM"},
		{Severity: "LOW"},
		{Severity: "UNKNOWN"},
		{Severity: "WEIRD"}, // 未定義 severity 也算 unknown
	}

	data := BuildReportData(sqlc.Scan{}, nil, findings)

	if data.Summary.Total != 7 {
		t.Errorf("Total = %d 預期 7", data.Summary.Total)
	}
	if data.Summary.Critical != 2 {
		t.Errorf("Critical = %d 預期 2", data.Summary.Critical)
	}
	if data.Summary.High != 1 {
		t.Errorf("High = %d 預期 1", data.Summary.High)
	}
	if data.Summary.Medium != 1 {
		t.Errorf("Medium = %d 預期 1", data.Summary.Medium)
	}
	if data.Summary.Low != 1 {
		t.Errorf("Low = %d 預期 1", data.Summary.Low)
	}
	if data.Summary.Unknown != 2 {
		t.Errorf("Unknown = %d 預期 2 (UNKNOWN + WEIRD)", data.Summary.Unknown)
	}
}

/* TestBuildReportDataEmpty 空 findings 摘要全為 0 */
func TestBuildReportDataEmpty(t *testing.T) {
	data := BuildReportData(sqlc.Scan{}, nil, nil)
	if data.Summary.Total != 0 {
		t.Errorf("空 findings Total 應為 0 實際 %d", data.Summary.Total)
	}
}

/* TestGenerateJSONValidOutput 產出應為合法 JSON 且含關鍵欄位 */
func TestGenerateJSONValidOutput(t *testing.T) {
	scan := sqlc.Scan{ID: "scan-1", Target: "/tmp/app"}
	runs := []sqlc.EngineRun{{Engine: "semgrep", Status: "completed"}}
	findings := []sqlc.Finding{
		{Engine: "semgrep", Severity: "HIGH", Title: "sql injection", FilePath: strPtr("db.go"), StartLine: intPtr(10)},
	}

	out, err := GenerateJSON(scan, runs, findings)
	if err != nil {
		t.Fatalf("GenerateJSON 失敗: %v", err)
	}

	/* 確認是合法 JSON 可被解析回來 */
	var parsed ReportData
	if err := json.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("產出非合法 JSON: %v", err)
	}

	if parsed.Scan.ID != "scan-1" {
		t.Errorf("scan ID = %q 預期 scan-1", parsed.Scan.ID)
	}
	if parsed.Summary.High != 1 {
		t.Errorf("High = %d 預期 1", parsed.Summary.High)
	}
	if len(parsed.Findings) != 1 {
		t.Errorf("findings 數 = %d 預期 1", len(parsed.Findings))
	}
	if parsed.Findings[0].Title != "sql injection" {
		t.Errorf("finding title = %q 預期 sql injection", parsed.Findings[0].Title)
	}
}

/* TestGenerateJSONEmptyFindings 無 findings 仍應產出合法 JSON */
func TestGenerateJSONEmptyFindings(t *testing.T) {
	out, err := GenerateJSON(sqlc.Scan{ID: "empty"}, nil, nil)
	if err != nil {
		t.Fatalf("空 findings GenerateJSON 失敗: %v", err)
	}
	if !strings.Contains(out, `"total": 0`) {
		t.Errorf("空 findings 應含 total 0 實際\n%s", out)
	}
}
