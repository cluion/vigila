package nmap

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* TestParse 解析 XML 確認 VA 欄位與只收 open port */
func TestParse(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sample.xml"))
	if err != nil {
		t.Fatalf("讀取 sample 失敗: %v", err)
	}

	s := &Scanner{}
	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse 失敗: %v", err)
	}

	/* sample 含 4 個 port 3 open 1 closed 應只收 3 個 */
	if len(findings) != 3 {
		t.Fatalf("期望 3 個 finding 實際 %d", len(findings))
	}

	/* ssh 22 有版本資訊 應為 MEDIUM */
	f1 := findings[0]
	if f1.Port != "22" {
		t.Errorf("Port 應為 22 實際 %s", f1.Port)
	}
	if f1.Severity != model.SeverityMedium {
		t.Errorf("有版本資訊應為 MEDIUM 實際 %s", f1.Severity)
	}
	if f1.Host != "scanme.nmap.org" {
		t.Errorf("Host 應為 scanme.nmap.org 實際 %s", f1.Host)
	}
	if f1.HashCode == "" {
		t.Error("HashCode 不應為空")
	}
	if f1.Snippet == "" {
		t.Error("ssh 應有版本 snippet")
	}

	/* nping-echo 9929 無版本資訊 應為 LOW */
	f3 := findings[2]
	if f3.Port != "9929" {
		t.Errorf("Port 應為 9929 實際 %s", f3.Port)
	}
	if f3.Severity != model.SeverityLow {
		t.Errorf("無版本資訊應為 LOW 實際 %s", f3.Severity)
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

/* TestBuildCommand 確認指令含 -sV 與 -oX - */
func TestBuildCommand(t *testing.T) {
	s := &Scanner{}
	binary, args := s.BuildCommand("192.168.1.10", scanner.Options{})
	if binary != "nmap" {
		t.Error("binary 應為 nmap")
	}
	joined := ""
	for _, a := range args {
		joined += a + " "
	}
	if !containsStr(joined, "-sV") {
		t.Error("應含 -sV")
	}
	if !containsStr(joined, "-oX - ") {
		t.Error("應含 -oX -")
	}
	if !containsStr(joined, "192.168.1.10") {
		t.Error("應含目標 host")
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
