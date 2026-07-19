package nuclei

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/*
	TestParseV3Format nuclei v3 的 info.tags 為陣列 須能解析不報錯

回歸測試 早期 struct 將 tags 定為 string 遇 v3 -jsonl 輸出即 unmarshal 失敗
*/
func TestParseV3Format(t *testing.T) {
	line := `{"template-id":"waf-detect","info":{"name":"WAF Detection","severity":"info","tags":["waf","tech","misc"],"reference":["https://x"]},"matched-at":"http://example.com","host":"example.com","type":"http"}`
	s := &Scanner{}
	findings, err := s.Parse([]byte(line))
	if err != nil {
		t.Fatalf("v3 格式解析失敗: %v", err)
	}
	if len(findings) != 1 || findings[0].RuleID != "waf-detect" {
		t.Fatalf("應解析出 1 筆 waf-detect 實際 %+v", findings)
	}
	if findings[0].URL != "http://example.com" {
		t.Errorf("URL 應取 matched-at 實際 %s", findings[0].URL)
	}
}

/* TestParse 解析 NDJSON 確認 DAST 欄位與 severity 映射正確 */
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

	/* Log4j RCE 應為 CRITICAL 有 matched URL */
	f1 := findings[0]
	if f1.RuleID != "CVE-2021-44228" {
		t.Errorf("RuleID 應為 CVE-2021-44228 實際 %s", f1.RuleID)
	}
	if f1.Severity != model.SeverityCritical {
		t.Errorf("Log4j 應為 CRITICAL 實際 %s", f1.Severity)
	}
	if f1.URL != "http://testphp.vulnweb.com/" {
		t.Errorf("URL 應為 http://testphp.vulnweb.com/ 實際 %s", f1.URL)
	}
	if f1.Title != "Log4j RCE" {
		t.Errorf("Title 應為 Log4j RCE")
	}
	if f1.HashCode == "" {
		t.Error("HashCode 不應為空")
	}
	if len(f1.References) == 0 {
		t.Error("Log4j 應有 reference")
	}

	/* tech-detect 為 info 應映射 LOW */
	f2 := findings[1]
	if f2.Severity != model.SeverityLow {
		t.Errorf("info 應映射 LOW 實際 %s", f2.Severity)
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

/* TestBuildCommand 確認指令含 -u 與 -jsonl */
func TestBuildCommand(t *testing.T) {
	s := &Scanner{}
	binary, args := s.BuildCommand("http://example.com", scanner.Options{})
	if binary != "nuclei" {
		t.Error("binary 應為 nuclei")
	}
	joined := ""
	for i, a := range args {
		if a == "-u" && i+1 < len(args) && args[i+1] == "http://example.com" {
			/* ok */
		}
		joined += a + " "
	}
	if !containsStr(joined, "-jsonl") {
		t.Error("應含 -jsonl")
	}
	if !containsStr(joined, "http://example.com") {
		t.Error("應含目標 URL")
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
