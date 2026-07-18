package zap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* TestParse 解析 ZAP 傳統 JSON 報告 確認 DAST 欄位與 riskcode 映射 */
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
	if len(findings) != 3 {
		t.Fatalf("期望 3 個 finding 實際 %d", len(findings))
	}

	/* XSS riskcode 3 → HIGH cwe 79 url 取 instance uri desc 去 HTML */
	xss := findings[0]
	if xss.RuleID != "40012" {
		t.Errorf("RuleID 應為 pluginid 40012 實際 %s", xss.RuleID)
	}
	if xss.Engine != binaryName || xss.Category != model.CategoryDAST {
		t.Errorf("engine/category 錯誤 %s %s", xss.Engine, xss.Category)
	}
	if xss.Severity != model.SeverityHigh {
		t.Errorf("riskcode 3 應為 HIGH 實際 %s", xss.Severity)
	}
	if xss.URL != "https://example.com/search?q=test" {
		t.Errorf("URL 應取 instance uri 實際 %s", xss.URL)
	}
	if xss.Method != "GET" {
		t.Errorf("Method 應為 GET 實際 %s", xss.Method)
	}
	if xss.CWE != "79" {
		t.Errorf("CWE 應為 79 實際 %s", xss.CWE)
	}
	if strings.Contains(xss.Description, "<p>") {
		t.Errorf("Description 應去除 HTML 標籤 實際 %s", xss.Description)
	}
	if len(xss.References) != 2 {
		t.Errorf("reference 應抽出 2 個 URL 實際 %d: %v", len(xss.References), xss.References)
	}
	if xss.HashCode == "" {
		t.Error("HashCode 不應為空")
	}

	/* header missing riskcode 1 → LOW */
	if findings[1].Severity != model.SeverityLow {
		t.Errorf("riskcode 1 應為 LOW 實際 %s", findings[1].Severity)
	}

	/* timestamp riskcode 0 informational → UNKNOWN */
	if findings[2].Severity != model.SeverityUnknown {
		t.Errorf("riskcode 0 informational 應為 UNKNOWN 實際 %s", findings[2].Severity)
	}
}

/* TestParseEmpty 無 site 或無 alerts 不出錯 */
func TestParseEmpty(t *testing.T) {
	s := &Scanner{}
	for _, in := range []string{`{"site":[]}`, `{"site":[{"@name":"x","alerts":[]}]}`} {
		findings, err := s.Parse([]byte(in))
		if err != nil {
			t.Fatalf("Parse %s 失敗: %v", in, err)
		}
		if len(findings) != 0 {
			t.Errorf("期望 0 個 finding 實際 %d", len(findings))
		}
	}
}

/* TestExitCodeIsFindings ZAP baseline warn 回非零 不以 exit code 判定發現 */
func TestExitCodeIsFindings(t *testing.T) {
	s := &Scanner{}
	if s.ExitCodeIsFindings(1) {
		t.Error("ZAP 不以 exit code 判定發現 應回 false")
	}
	if s.ExitCodeIsFindings(2) {
		t.Error("ZAP 不以 exit code 判定發現 應回 false")
	}
}

/* TestBuildCommand 指令含 -cmd -quickurl 目標 與 -quickout 報告檔 */
func TestBuildCommand(t *testing.T) {
	s := &Scanner{}
	binary, args := s.BuildCommand("https://example.com", scanner.Options{})
	if binary != "zap.sh" {
		t.Errorf("binary 應為 zap.sh 實際 %s", binary)
	}
	joined := strings.Join(args, " ")
	if !strings.Contains(joined, "-quickurl https://example.com") {
		t.Errorf("指令應含 -quickurl 目標 實際 %s", joined)
	}
	if !strings.Contains(joined, "-quickout") || !strings.Contains(joined, ".json") {
		t.Errorf("指令應含 -quickout .json 實際 %s", joined)
	}
}

/* TestStripHTML 去除標籤並收斂空白 */
func TestStripHTML(t *testing.T) {
	got := stripHTML("<p>hello</p>\n<p>world</p>")
	if strings.Contains(got, "<") || !strings.Contains(got, "hello") || !strings.Contains(got, "world") {
		t.Errorf("stripHTML 結果不正確: %q", got)
	}
}
