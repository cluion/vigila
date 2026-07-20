package report

import (
	"strings"
	"testing"

	"github.com/cluion/vigila/internal/store/sqlc"
)

/* TestGenerateHTMLBasic 產出含 scan ID 目標 與 finding 內容 */
func TestGenerateHTMLBasic(t *testing.T) {
	scan := sqlc.Scan{ID: "scan-html", Target: "/tmp/app"}
	runs := []sqlc.EngineRun{{Engine: "semgrep", Category: "SAST", Status: "completed", DurationMs: intPtr(120)}}
	findings := []sqlc.Finding{
		{
			Engine:    "semgrep",
			Category:  "SAST",
			Severity:  "HIGH",
			Title:     "command injection",
			RuleID:    "python.dangerous-exec",
			FilePath:  strPtr("app/run.py"),
			StartLine: intPtr(42),
		},
	}

	out, err := GenerateHTML(scan, runs, findings)
	if err != nil {
		t.Fatalf("GenerateHTML 失敗: %v", err)
	}

	for _, want := range []string{"scan-html", "/tmp/app", "command injection", "b-HIGH", "app/run.py", "第 42 行", "python.dangerous-exec"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML 缺少 %q", want)
		}
	}
}

/* TestGenerateHTMLEmptyFindings 無 findings 應顯示「沒有發現漏洞」並仍含摘要卡 */
func TestGenerateHTMLEmptyFindings(t *testing.T) {
	out, err := GenerateHTML(sqlc.Scan{ID: "clean"}, nil, nil)
	if err != nil {
		t.Fatalf("空 findings GenerateHTML 失敗: %v", err)
	}
	if !strings.Contains(out, "沒有發現漏洞") {
		t.Errorf("空 findings 應顯示「沒有發現漏洞」")
	}
	/* 摘要卡仍應渲染 含總計 0 */
	if !strings.Contains(out, "總計") {
		t.Errorf("空 findings 仍應含摘要卡總計")
	}
}

/* TestGenerateHTMLLocationVariants 各類 finding 的位置欄應正確渲染 */
func TestGenerateHTMLLocationVariants(t *testing.T) {
	findings := []sqlc.Finding{
		{Severity: "LOW", Engine: "trivy", FilePath: strPtr("lock.json"), PkgName: strPtr("lodash"), InstalledVersion: strPtr("1.2.3")}, // SCA
		{Severity: "CRITICAL", Engine: "nuclei", Url: strPtr("https://x.com/admin")},                                                    // DAST
		{Severity: "MEDIUM", Engine: "nmap", Host: strPtr("10.0.0.1"), Port: strPtr("22")},                                              // VA
	}

	out, err := GenerateHTML(sqlc.Scan{ID: "loc"}, nil, findings)
	if err != nil {
		t.Fatalf("GenerateHTML 失敗: %v", err)
	}

	for _, want := range []string{"lodash", "1.2.3", "https://x.com/admin", "10.0.0.1:22"} {
		if !strings.Contains(out, want) {
			t.Errorf("HTML 位置欄缺少 %q", want)
		}
	}
}

/* TestGenerateHTMLFixedVersion 修復版本應渲染為 fix 標示 */
func TestGenerateHTMLFixedVersion(t *testing.T) {
	findings := []sqlc.Finding{
		{Severity: "HIGH", Engine: "trivy", Title: "CVE-2024-1234", FixedVersion: strPtr(">=2.0.0")},
	}
	out, err := GenerateHTML(sqlc.Scan{ID: "fix"}, nil, findings)
	if err != nil {
		t.Fatalf("GenerateHTML 失敗: %v", err)
	}
	if !strings.Contains(out, "修復版本") || !strings.Contains(out, "&gt;=2.0.0") {
		t.Errorf("HTML 應含修復版本標示（>= 會被 escape 為 &gt;=）實際缺")
	}
}

/* TestGenerateHTMLXSSFindingContent finding 內容應被 HTML escape 不注入 */
func TestGenerateHTMLXSSFindingContent(t *testing.T) {
	findings := []sqlc.Finding{
		{
			Severity: "HIGH",
			Title:    `<script>alert("xss")</script>`,
			Snippet:  strPtr(`<img src=x onerror=alert(1)>`),
		},
	}
	out, err := GenerateHTML(sqlc.Scan{ID: "xss"}, nil, findings)
	if err != nil {
		t.Fatalf("GenerateHTML 失敗: %v", err)
	}
	/* 原始 <script> 標籤不應出現 應被 escape 為 &lt;script&gt; */
	if strings.Contains(out, "<script>alert") {
		t.Errorf("HTML 未 escape finding title XSS 注入風險")
	}
	if strings.Contains(out, "<img src=x onerror") {
		t.Errorf("HTML 未 escape finding snippet XSS 注入風險")
	}
}
