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

/*
	TestParseVulnScripts 解析含 NSE vuln 腳本的 XML 驗證 CVE 與腳本 finding

port 22 vulners 兩個 CVE 各成一筆 severity 取 CVSS
port 80 兩支腳本 http-csrf 無 VULNERABLE 為 LOW slowloris 含 VULNERABLE 為 HIGH
每個開放 port 仍先產一筆 nmap-service finding
*/
func TestParseVulnScripts(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "vuln.xml"))
	if err != nil {
		t.Fatalf("讀取 vuln fixture 失敗: %v", err)
	}

	s := &Scanner{}
	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse 失敗: %v", err)
	}

	/* 2 開放 port 各 1 service + port22 2 CVE + port80 2 腳本 = 2+2+2 = 6 */
	if len(findings) != 6 {
		t.Fatalf("期望 6 筆 finding 實際 %d", len(findings))
	}

	byRule := map[string]model.Finding{}
	for _, f := range findings {
		if f.Host != "scanme.example.org" {
			t.Errorf("host 不符 實際 %s", f.Host)
		}
		byRule[f.RuleID] = f
	}

	/* CVE finding severity 由 CVSS 換算 CVE-2019-6111 cvss 5.8 → MEDIUM */
	cve, ok := byRule["CVE-2019-6111"]
	if !ok {
		t.Fatal("應有 CVE-2019-6111 finding")
	}
	if cve.Severity != model.SeverityMedium {
		t.Errorf("CVSS 5.8 應為 MEDIUM 實際 %s", cve.Severity)
	}
	if cve.Port != "22" || cve.CVSSScore == nil || *cve.CVSSScore != 5.8 {
		t.Errorf("CVE finding 欄位不符 port=%s cvss=%v", cve.Port, cve.CVSSScore)
	}
	if len(cve.References) != 1 || cve.References[0] != "CVE-2019-6111" {
		t.Errorf("CVE 應入 references 實際 %v", cve.References)
	}

	/* 含 VULNERABLE 的腳本為 HIGH 無的為 LOW */
	if slow := byRule["nmap-http-slowloris-check"]; slow.Severity != model.SeverityHigh {
		t.Errorf("含 VULNERABLE 應為 HIGH 實際 %s", slow.Severity)
	}
	if csrf := byRule["nmap-http-csrf"]; csrf.Severity != model.SeverityLow {
		t.Errorf("無 VULNERABLE 應為 LOW 實際 %s", csrf.Severity)
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
	if !containsStr(joined, "--script vuln") {
		t.Error("應含 --script vuln")
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
