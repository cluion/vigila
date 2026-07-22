package nikto

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* TestParse 解析 JSON 確認 DAST 欄位 跳過無 id 的雜訊列 */
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

	/* sample 有 3 個 vuln 其中 1 個無 id 應被跳過 剩 2 個 */
	if len(findings) != 2 {
		t.Fatalf("期望 2 個 finding 實際 %d", len(findings))
	}

	f := findings[0]
	if f.Engine != "nikto" || f.Category != model.CategoryDAST {
		t.Errorf("engine/category 不符 得 %s/%s", f.Engine, f.Category)
	}
	if f.RuleID != "999957" {
		t.Errorf("RuleID 應為 999957 實際 %s", f.RuleID)
	}
	if f.Severity != model.SeverityLow {
		t.Errorf("nikto 無 severity 應為 LOW 實際 %s", f.Severity)
	}
	if f.Host != "testphp.vulnweb.com" || f.Port != "80" {
		t.Errorf("host/port 不符 得 %s:%s", f.Host, f.Port)
	}
	if f.URL != "http://testphp.vulnweb.com/" {
		t.Errorf("URL 組合不符 實際 %s", f.URL)
	}
	if len(f.References) != 1 {
		t.Errorf("應有 1 個 reference 實際 %d", len(f.References))
	}
	if f.HashCode == "" {
		t.Error("HashCode 不應為空")
	}

	/* 第二筆 admin 目錄 url 應含路徑 */
	if findings[1].URL != "http://testphp.vulnweb.com/admin/" {
		t.Errorf("第二筆 URL 不符 實際 %s", findings[1].URL)
	}
}

/*
	TestParseRealOutput 以真實 nikto 掃描輸出驗證解析（regression fixture）

fixture 取自 nikto 2.5.0 對 nginx:alpine 的實際 JSON 報告 6 筆伺服器 header 發現
確保手寫 fixture 與真實工具輸出格式一致 防欄位漂移
*/
func TestParseRealOutput(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "real_nginx.json"))
	if err != nil {
		t.Fatalf("讀取真實 fixture 失敗: %v", err)
	}

	s := &Scanner{}
	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse 真實輸出失敗: %v", err)
	}

	if len(findings) != 6 {
		t.Fatalf("真實輸出期望 6 筆 finding 實際 %d", len(findings))
	}
	for i, f := range findings {
		if f.Engine != "nikto" || f.Severity != model.SeverityLow {
			t.Errorf("第 %d 筆 engine/severity 不符 得 %s/%s", i, f.Engine, f.Severity)
		}
		if f.Host != "smoke-nginx" || f.Port != "80" {
			t.Errorf("第 %d 筆 host/port 不符 得 %s:%s", i, f.Host, f.Port)
		}
		if f.RuleID == "" || f.Title == "" || f.HashCode == "" {
			t.Errorf("第 %d 筆 必要欄位為空 %+v", i, f)
		}
		if len(f.References) != 1 {
			t.Errorf("第 %d 筆 應有 1 個 reference 實際 %d", i, len(f.References))
		}
	}
}

/* TestParseSingleObject 確認相容單一物件頂層形狀 */
func TestParseSingleObject(t *testing.T) {
	raw := []byte(`{"host":"x","port":"443","vulnerabilities":[{"id":"1","method":"GET","url":"/a","msg":"m"}]}`)
	s := &Scanner{}
	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse 單物件失敗: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("期望 1 個 finding 實際 %d", len(findings))
	}
	/* 443 埠應推導 https 且不帶埠號 */
	if findings[0].URL != "https://x/a" {
		t.Errorf("https 推導不符 實際 %s", findings[0].URL)
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

/* TestBuildCommand 確認指令含 -h -Format json -output */
func TestBuildCommand(t *testing.T) {
	s := &Scanner{}
	binary, args := s.BuildCommand("http://x", scanner.Options{})
	if binary != "nikto" {
		t.Error("binary 應為 nikto")
	}
	joined := strings.Join(args, " ")
	for _, want := range []string{"-h http://x", "-Format json", "-output", "-nointeractive"} {
		if !strings.Contains(joined, want) {
			t.Errorf("指令應含 %q 實際 %s", want, joined)
		}
	}
}

/* TestExitCodeIsFindings 確認 nikto 不以 exit code 表達發現 */
func TestExitCodeIsFindings(t *testing.T) {
	s := &Scanner{}
	if s.ExitCodeIsFindings(1) {
		t.Error("nikto 不應以 exit code 表達發現")
	}
}
