package cli

import (
	"bytes"
	"testing"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/sbom"
	"github.com/cluion/vigila/internal/store/sqlc"
)

/* strptr 回傳字串指標 供 sqlc 可空欄位 */
func strptr(s string) *string { return &s }

func TestPrintSummary(t *testing.T) {
	var buf bytes.Buffer
	printSummary(&buf, &core.ScanResult{
		ScanID:     "s1",
		Total:      3,
		DurationMs: 1200,
		BySeverity: map[model.Severity]int{
			model.SeverityCritical: 1,
			model.SeverityHigh:     2,
		},
		ByEngine:     map[string]int{"semgrep": 2, "gitleaks": 1},
		SBOMPackages: 42,
	})
	out := buf.String()
	for _, want := range []string{"s1", "1200ms", "發現: 3", "CRITICAL", "引擎分布", "SBOM: 42"} {
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Errorf("printSummary 輸出應含 %q 實際 %s", want, out)
		}
	}
}

func TestPrintSummarySBOMError(t *testing.T) {
	var buf bytes.Buffer
	printSummary(&buf, &core.ScanResult{ScanID: "s3", Total: 0, SBOMErr: errSBOM})
	if !bytes.Contains(buf.Bytes(), []byte("SBOM: 未產生")) {
		t.Errorf("SBOM 錯誤應提示未產生 實際 %s", buf.String())
	}
}

/* errSBOM 為測試用 SBOM 錯誤 */
var errSBOM = errTest("sbom 失敗")

type errTest string

func (e errTest) Error() string { return string(e) }

func TestPrintSummaryNoFindings(t *testing.T) {
	var buf bytes.Buffer
	printSummary(&buf, &core.ScanResult{ScanID: "s2", Total: 0, DurationMs: 5})
	if !bytes.Contains(buf.Bytes(), []byte("發現: 0")) {
		t.Errorf("零發現輸出不符 %s", buf.String())
	}
}

func TestPrintDiff(t *testing.T) {
	var buf bytes.Buffer
	printDiff(&buf, &core.DiffResult{
		From:      sqlc.Scan{ID: "a"},
		To:        sqlc.Scan{ID: "b"},
		Added:     []sqlc.Finding{{ID: "f1", Title: "新洞", Severity: "HIGH", FilePath: strptr("main.go")}},
		Removed:   []sqlc.Finding{{ID: "f2", Title: "修好的", Severity: "LOW"}},
		Unchanged: 5,
	})
	out := buf.String()
	for _, want := range []string{"a → b", "新增: 1", "消失: 1", "新洞", "main.go"} {
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Errorf("printDiff 應含 %q 實際 %s", want, out)
		}
	}
}

func TestPrintSBOMDiff(t *testing.T) {
	var buf bytes.Buffer
	printSBOMDiff(&buf, &core.SBOMDiffResult{
		From:      sqlc.Scan{ID: "a"},
		To:        sqlc.Scan{ID: "b"},
		FromTotal: 10,
		ToTotal:   11,
		Diff: sbom.Diff{
			Added:     []sbom.Package{{Name: "left-pad", Version: "1.0.0"}},
			Removed:   []sbom.Package{{Name: "old-lib", Version: "0.1.0"}},
			Changed:   []sbom.PackageChange{{Name: "lodash", OldVersion: "4.17.20", NewVersion: "4.17.21"}},
			Unchanged: 8,
		},
	})
	out := buf.String()
	for _, want := range []string{"a → b", "10 → 11", "left-pad", "old-lib", "lodash", "4.17.21"} {
		if !bytes.Contains(buf.Bytes(), []byte(want)) {
			t.Errorf("printSBOMDiff 應含 %q 實際 %s", want, out)
		}
	}
}
