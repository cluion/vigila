package openvas

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* TestParse 解析 GMP 報告 XML 確認 VA 欄位與 severity 換算 */
func TestParse(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "report.xml"))
	if err != nil {
		t.Fatalf("讀取 report 失敗: %v", err)
	}

	s := &Scanner{}
	findings, err := s.Parse(raw)
	if err != nil {
		t.Fatalf("Parse 失敗: %v", err)
	}

	if len(findings) != 3 {
		t.Fatalf("期望 3 個 finding 實際 %d", len(findings))
	}

	/* 第一筆 TLS CVSS 4.3 → MEDIUM 埠 443 帶 CVE */
	f0 := findings[0]
	if f0.Engine != "openvas" || f0.Category != model.CategoryVA {
		t.Errorf("engine/category 不符 得 %s/%s", f0.Engine, f0.Category)
	}
	if f0.Severity != model.SeverityMedium {
		t.Errorf("CVSS 4.3 應為 MEDIUM 實際 %s", f0.Severity)
	}
	if f0.Host != "192.168.56.101" {
		t.Errorf("Host 應由 host 文字節點取得 實際 %q", f0.Host)
	}
	if f0.Port != "443" {
		t.Errorf("Port 應為 443 實際 %s", f0.Port)
	}
	if f0.RuleID != "1.3.6.1.4.1.25623.1.0.117274" {
		t.Errorf("RuleID 應為 NVT OID 實際 %s", f0.RuleID)
	}
	if f0.CVSSScore == nil || *f0.CVSSScore != 4.3 {
		t.Errorf("CVSSScore 應為 4.3 實際 %v", f0.CVSSScore)
	}
	if len(f0.References) != 1 || f0.References[0] != "CVE-2011-3389" {
		t.Errorf("應只收 CVE 參照 實際 %v", f0.References)
	}
	if f0.HashCode == "" {
		t.Error("HashCode 不應為空")
	}

	/* 第二筆 SSH CVSS 9.8 → CRITICAL */
	if findings[1].Severity != model.SeverityCritical {
		t.Errorf("CVSS 9.8 應為 CRITICAL 實際 %s", findings[1].Severity)
	}

	/* 第三筆 Log CVSS 0 → UNKNOWN 埠 general/tcp 保留原值無 CVSS */
	f2 := findings[2]
	if f2.Severity != model.SeverityUnknown {
		t.Errorf("Log 且 CVSS 0 應為 UNKNOWN 實際 %s", f2.Severity)
	}
	if f2.Port != "general/tcp" {
		t.Errorf("無埠號應保留原值 實際 %s", f2.Port)
	}
	if f2.CVSSScore != nil {
		t.Errorf("CVSS 0 不應設分數 實際 %v", f2.CVSSScore)
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

/* TestBuildGMPCommands 確認 GMP 指令含正確物件 id 與逃脫 */
func TestBuildGMPCommands(t *testing.T) {
	ct := buildCreateTarget("vigila-x", "10.0.0.1")
	if !strings.Contains(ct, portListAllTCP) || !strings.Contains(ct, "<hosts>10.0.0.1</hosts>") {
		t.Errorf("create_target 不符 實際 %s", ct)
	}
	task := buildCreateTask("vigila-x", "tgt-id")
	if !strings.Contains(task, configFullFast) || !strings.Contains(task, `target id="tgt-id"`) {
		t.Errorf("create_task 不符 實際 %s", task)
	}
	if !strings.Contains(buildStartTask("t1"), `task_id="t1"`) {
		t.Error("start_task 應含 task_id")
	}
	if !strings.Contains(buildGetReport("r1"), `report_id="r1"`) {
		t.Error("get_report 應含 report_id")
	}
}

/* TestXMLEscapeTarget 確認目標值做 XML 逃脫防注入 */
func TestXMLEscapeTarget(t *testing.T) {
	ct := buildCreateTarget("n", `1.1.1.1"/><evil>`)
	if strings.Contains(ct, "<evil>") {
		t.Errorf("目標值應被逃脫 實際 %s", ct)
	}
}

/*
	fakeGMP 依指令關鍵字回預設 GMP 回應 供測試 orchestrate 全流程不需真容器

statusMap 讓測試指定各步驟回應 responses 記錄呼叫過的指令供斷言
*/
type fakeGMP struct {
	reportXML []byte
	calls     []string
	taskPolls int
}

func (f *fakeGMP) run(_ context.Context, xmlCmd string) ([]byte, error) {
	f.calls = append(f.calls, xmlCmd)
	switch {
	case strings.HasPrefix(xmlCmd, "<create_target"):
		return []byte(`<create_target_response status="201" status_text="OK" id="tgt-1"/>`), nil
	case strings.HasPrefix(xmlCmd, "<create_task"):
		return []byte(`<create_task_response status="201" status_text="OK" id="task-1"/>`), nil
	case strings.HasPrefix(xmlCmd, "<start_task"):
		return []byte(`<start_task_response status="202" status_text="OK"><report_id>rep-1</report_id></start_task_response>`), nil
	case strings.HasPrefix(xmlCmd, "<get_tasks"):
		f.taskPolls++
		/* 首查 Running 次查 Done 驗證輪詢會續等 */
		if f.taskPolls < 2 {
			return []byte(`<get_tasks_response status="200"><task><status>Running</status><progress>40</progress></task></get_tasks_response>`), nil
		}
		return []byte(`<get_tasks_response status="200"><task><status>Done</status><progress>-1</progress></task></get_tasks_response>`), nil
	case strings.HasPrefix(xmlCmd, "<get_reports"):
		return f.reportXML, nil
	}
	return nil, nil
}

/* TestOrchestrateFlow 用 fakeGMP 跑完整流程 確認回報告 XML 且各步驟被呼叫 */
func TestOrchestrateFlow(t *testing.T) {
	report := []byte(`<get_reports_response status="200"><report><report><results><result id="r"><host>1.2.3.4</host><port>80/tcp</port><nvt oid="o"><cvss_base>5.0</cvss_base></nvt><threat>Medium</threat><severity>5.0</severity><description>d</description></result></results></report></report></get_reports_response>`)
	f := &fakeGMP{reportXML: report}

	/* 調小輪詢間隔避免測試空等 用後還原 */
	restore := pollInterval
	pollInterval = time.Millisecond
	defer func() { pollInterval = restore }()

	out, err := orchestrate(context.Background(), f, "1.2.3.4")
	if err != nil {
		t.Fatalf("orchestrate 失敗: %v", err)
	}

	s := &Scanner{}
	findings, err := s.Parse(out)
	if err != nil {
		t.Fatalf("Parse orchestrate 結果失敗: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("期望 1 個 finding 實際 %d", len(findings))
	}
	if f.taskPolls < 2 {
		t.Errorf("應至少輪詢 2 次 實際 %d", f.taskPolls)
	}
}

/* TestScannerRunWithInjectedClient 確認 Run 用注入的 client 完成流程 */
func TestScannerRunWithInjectedClient(t *testing.T) {
	restore := pollInterval
	pollInterval = time.Millisecond
	defer func() { pollInterval = restore }()

	report := []byte(`<get_reports_response status="200"><report><report><results></results></report></report></get_reports_response>`)
	s := &Scanner{client: &fakeGMP{reportXML: report}}

	res, err := s.Run(context.Background(), "1.2.3.4", scanner.Options{})
	if err != nil {
		t.Fatalf("Run 失敗: %v", err)
	}
	if len(res.RawOutput) == 0 {
		t.Error("RawOutput 不應為空")
	}
}
