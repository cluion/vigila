package sqlmap

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* TestParse 解析 sqlmap stdout 確認注入點與 DAST 欄位 */
func TestParse(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sample.txt"))
	if err != nil {
		t.Fatalf("讀取 sample 失敗: %v", err)
	}

	s := &Scanner{}
	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse 失敗: %v", err)
	}

	/* sample 有一個可注入參數 artist */
	if len(findings) != 1 {
		t.Fatalf("期望 1 個 finding 實際 %d", len(findings))
	}

	f := findings[0]
	if f.Engine != "sqlmap" || f.Category != model.CategoryDAST {
		t.Errorf("engine/category 不符 得 %s/%s", f.Engine, f.Category)
	}
	if f.Severity != model.SeverityHigh {
		t.Errorf("SQL 注入應為 HIGH 實際 %s", f.Severity)
	}
	if !strings.Contains(f.Title, "artist") || !strings.Contains(f.Title, "GET") {
		t.Errorf("Title 應含參數與方法 實際 %s", f.Title)
	}
	if f.Method != "GET" {
		t.Errorf("Method 應為 GET 實際 %s", f.Method)
	}
	if f.URL != "http://testphp.vulnweb.com/artists.php?artist=1" {
		t.Errorf("URL 應由標記還原 實際 %s", f.URL)
	}
	if f.Host != "testphp.vulnweb.com" {
		t.Errorf("Host 應由 URL 推導 實際 %s", f.Host)
	}
	/* 三種注入手法應入描述 */
	for _, want := range []string{"boolean-based blind", "error-based", "UNION query"} {
		if !strings.Contains(f.Description, want) {
			t.Errorf("Description 應含 %q 實際 %s", want, f.Description)
		}
	}
	if f.HashCode == "" {
		t.Error("HashCode 不應為空")
	}
}

/* TestParseMultiParam 確認多參數各成一筆 finding */
func TestParseMultiParam(t *testing.T) {
	raw := []byte(`vigila-target: http://x/p?a=1&b=2
---
Parameter: a (GET)
    Type: UNION query
    Title: t1

Parameter: b (POST)
    Type: error-based
    Title: t2
---
`)
	s := &Scanner{}
	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse 失敗: %v", err)
	}
	if len(findings) != 2 {
		t.Fatalf("期望 2 個 finding 實際 %d", len(findings))
	}
	if findings[0].UniqueIDFromTool != "sqli:a:GET" || findings[1].UniqueIDFromTool != "sqli:b:POST" {
		t.Errorf("UniqueIDFromTool 不符 得 %s / %s", findings[0].UniqueIDFromTool, findings[1].UniqueIDFromTool)
	}
}

/* TestParseNoInjection 確認無注入點時回空 不誤報 */
func TestParseNoInjection(t *testing.T) {
	raw := []byte(`vigila-target: http://x/p?a=1
[12:00:03] [INFO] GET parameter 'a' does not seem to be injectable
[*] ending @ 12:00:04
`)
	s := &Scanner{}
	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse 失敗: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("無注入點應回 0 個 finding 實際 %d", len(findings))
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

/* TestBuildCommand 確認指令含 -u --batch --disable-coloring */
func TestBuildCommand(t *testing.T) {
	s := &Scanner{}
	binary, args := s.BuildCommand("http://x?a=1", scanner.Options{})
	if binary != "sqlmap" {
		t.Error("binary 應為 sqlmap")
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"-u http://x?a=1", "--batch", "--disable-coloring"} {
		if !strings.Contains(joined, want) {
			t.Errorf("指令應含 %q 實際 %s", want, joined)
		}
	}
}
