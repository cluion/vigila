// Package openvas 為 OpenVAS/Greenbone(GVM) 弱點掃描器 VA adapter
//
// OpenVAS 非單一 binary 而是常駐服務堆疊 掃描透過 GMP(Greenbone Management Protocol)
// 建 target/task 啟動後輪詢完成再取報告 本 adapter 以 docker compose exec 呼叫容器內
// gvm-cli 走 GMP socket 完成整條流程 target 為 host 或 IP
//
// 僅支援 docker 執行（immauss/openvas 單容器全套）需先在面板勾選 openvas docker profile
// 報告為 GMP get_reports XML 每個 result 一筆 finding severity 取 CVSS 分數
// 授權 GVM 為 GPL Vigila 以 subprocess 呼叫不連結程式碼 不影響 MIT 授權
package openvas

import (
	"context"
	"encoding/xml"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

const engineName = "openvas"

/*
	GMP 掃描所需的內建物件 ID 為 GVM 各版本固定的預設值

portList 全 IANA TCP 埠 scanConfig Full and fast 平衡涵蓋與時間 scanner OpenVAS Default
*/
const (
	portListAllTCP = "33d0cd82-57c6-11e1-8ed1-406186ea4fc5"
	configFullFast = "daba56c8-73ec-11df-a475-002264764cea"
	scannerDefault = "08b69003-5fc2-4037-a479-93b440211c73"
	gmpSocketPath  = "/run/gvmd/gvmd.sock"
)

/* pollInterval 為輪詢 task 狀態的間隔 掃描動輒數分鐘 不需密集查詢 測試可覆寫 */
var pollInterval = 15 * time.Second

/* Scanner 為 OpenVAS adapter 實作 */
type Scanner struct {
	/* client 為 GMP 呼叫通道 nil 時用 docker compose exec 實作 供測試覆寫 */
	client gmp
}

func init() { scanner.Register(&Scanner{}) }

func (s *Scanner) Name() string             { return engineName }
func (s *Scanner) Category() model.Category { return model.CategoryVA }
func (s *Scanner) Binary() string           { return engineName }
func (s *Scanner) VersionArgs() []string    { return []string{"--version"} }

/* TargetKinds openvas 掃描網路主機 只吃 host IP */
func (s *Scanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetHost}
}

/* InstallHint openvas 僅支援 docker 執行 引導至面板 Docker 開關 */
func (s *Scanner) InstallHint() scanner.InstallHint {
	return scanner.InstallHint{
		DocsURL: "https://greenbone.github.io/docs/",
		Command: "在引擎面板開啟 openvas 的 Docker 開關",
	}
}

/* CheckInstalled openvas 為 docker-only 需已勾選 openvas docker profile */
func (s *Scanner) CheckInstalled() error {
	if scanner.DockerProfileEnabled(engineName) {
		return nil
	}
	return fmt.Errorf("openvas 僅支援 docker 執行 請先在引擎面板開啟 openvas 的 Docker 開關")
}

/*
	BuildCommand openvas 不以單一指令執行 而是多步 GMP 流程

回傳僅為介面完整性與顯示用途 實際流程見 Run
*/
func (s *Scanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	return "gvm-cli", []string{"socket", "--target", target}
}

/*
	Run 執行 GMP 掃描流程 建 target/task 啟動 輪詢完成後取報告 XML

client 未注入時用 docker compose exec 呼叫容器內 gvm-cli
掃描時間長 呼叫端 context 逾時或取消可中止輪詢
*/
func (s *Scanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	start := time.Now()
	client := s.client
	if client == nil {
		client = newDockerGMP()
	}

	report, err := orchestrate(ctx, client, target)
	if err != nil {
		return nil, err
	}
	return &scanner.Result{
		RawOutput:  report,
		ExitCode:   0,
		DurationMs: time.Since(start).Milliseconds(),
		Command:    "gvm-cli GMP scan " + target,
	}, nil
}

/* ExitCodeIsFindings openvas 走 GMP 不以 exit code 表達發現 一律 false */
func (s *Scanner) ExitCodeIsFindings(code int) bool {
	return false
}

/*
	orchestrate 跑完整 GMP 掃描流程 回傳報告 XML

建 target → 建 task → 啟動取 report_id → 輪詢至 Done → 取報告
任一步驟的 GMP 狀態非成功即回錯 中止流程
*/
func orchestrate(ctx context.Context, client gmp, target string) ([]byte, error) {
	name := "vigila-" + target

	targetID, err := createEntity(ctx, client, buildCreateTarget(name, target), "create_target_response")
	if err != nil {
		return nil, fmt.Errorf("建立 GMP target 失敗: %w", err)
	}
	taskID, err := createEntity(ctx, client, buildCreateTask(name, targetID), "create_task_response")
	if err != nil {
		return nil, fmt.Errorf("建立 GMP task 失敗: %w", err)
	}

	reportID, err := startTask(ctx, client, taskID)
	if err != nil {
		return nil, fmt.Errorf("啟動 GMP task 失敗: %w", err)
	}

	if err := waitForTask(ctx, client, taskID); err != nil {
		return nil, err
	}

	report, err := client.run(ctx, buildGetReport(reportID))
	if err != nil {
		return nil, fmt.Errorf("取得 GMP 報告失敗: %w", err)
	}
	return report, nil
}

/* createEntity 執行建立類 GMP 指令並回傳新物件 id 檢查回應狀態 */
func createEntity(ctx context.Context, client gmp, xmlCmd, respTag string) (string, error) {
	out, err := client.run(ctx, xmlCmd)
	if err != nil {
		return "", err
	}
	var resp gmpCreateResponse
	if err := xml.Unmarshal(out, &resp); err != nil {
		return "", fmt.Errorf("解析 %s 失敗: %w", respTag, err)
	}
	if !statusOK(resp.Status) {
		return "", fmt.Errorf("GMP 回應狀態 %s %s", resp.Status, resp.StatusText)
	}
	if resp.ID == "" {
		return "", fmt.Errorf("GMP 回應未含新物件 id")
	}
	return resp.ID, nil
}

/* startTask 啟動 task 回傳其 report_id */
func startTask(ctx context.Context, client gmp, taskID string) (string, error) {
	out, err := client.run(ctx, buildStartTask(taskID))
	if err != nil {
		return "", err
	}
	var resp gmpStartTaskResponse
	if err := xml.Unmarshal(out, &resp); err != nil {
		return "", fmt.Errorf("解析 start_task_response 失敗: %w", err)
	}
	if !statusOK(resp.Status) {
		return "", fmt.Errorf("GMP 回應狀態 %s %s", resp.Status, resp.StatusText)
	}
	if resp.ReportID == "" {
		return "", fmt.Errorf("start_task 未回 report_id")
	}
	return resp.ReportID, nil
}

/*
	waitForTask 輪詢 task 狀態至完成

Done 為成功 Stopped/Interrupted 視為失敗 其餘（Running/Requested）續等
以 context 控制逾時與取消 每 pollInterval 查一次
*/
func waitForTask(ctx context.Context, client gmp, taskID string) error {
	for {
		out, err := client.run(ctx, buildGetTask(taskID))
		if err != nil {
			return fmt.Errorf("查詢 GMP task 狀態失敗: %w", err)
		}
		var resp gmpGetTasksResponse
		if err := xml.Unmarshal(out, &resp); err != nil {
			return fmt.Errorf("解析 get_tasks_response 失敗: %w", err)
		}

		switch resp.Task.Status {
		case "Done":
			return nil
		case "Stopped", "Interrupted", "Failed":
			return fmt.Errorf("GMP task 未正常完成 狀態 %s", resp.Task.Status)
		}

		select {
		case <-ctx.Done():
			return fmt.Errorf("等待 GMP task 完成逾時或取消: %w", ctx.Err())
		case <-time.After(pollInterval):
		}
	}
}

/* statusOK GMP 成功狀態為 2xx create 類回 201 查詢類回 200 */
func statusOK(status string) bool {
	return strings.HasPrefix(status, "2")
}

/* buildCreateTarget 組 create_target GMP 指令 hosts 為掃描目標 埠清單用全 IANA TCP */
func buildCreateTarget(name, host string) string {
	return fmt.Sprintf(
		`<create_target><name>%s</name><hosts>%s</hosts><port_list id="%s"/></create_target>`,
		xmlEscape(name), xmlEscape(host), portListAllTCP,
	)
}

/* buildCreateTask 組 create_task GMP 指令 用 Full and fast config 與預設 scanner */
func buildCreateTask(name, targetID string) string {
	return fmt.Sprintf(
		`<create_task><name>%s</name><config id="%s"/><target id="%s"/><scanner id="%s"/></create_task>`,
		xmlEscape(name), configFullFast, targetID, scannerDefault,
	)
}

/* buildStartTask 組 start_task GMP 指令 */
func buildStartTask(taskID string) string {
	return fmt.Sprintf(`<start_task task_id="%s"/>`, taskID)
}

/* buildGetTask 組查單一 task 狀態的 GMP 指令 */
func buildGetTask(taskID string) string {
	return fmt.Sprintf(`<get_tasks task_id="%s"/>`, taskID)
}

/* buildGetReport 組取報告的 GMP 指令 帶 details 取完整結果 XML 格式 */
func buildGetReport(reportID string) string {
	return fmt.Sprintf(`<get_reports report_id="%s" details="1"/>`, reportID)
}

/* xmlEscape 對 GMP 指令中的動態值做 XML 逃脫 防注入 */
func xmlEscape(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

/* --- GMP 回應解析結構 --- */

type gmpCreateResponse struct {
	Status     string `xml:"status,attr"`
	StatusText string `xml:"status_text,attr"`
	ID         string `xml:"id,attr"`
}

type gmpStartTaskResponse struct {
	Status     string `xml:"status,attr"`
	StatusText string `xml:"status_text,attr"`
	ReportID   string `xml:"report_id"`
}

type gmpGetTasksResponse struct {
	Status string  `xml:"status,attr"`
	Task   gmpTask `xml:"task"`
}

type gmpTask struct {
	Status   string `xml:"status"`
	Progress string `xml:"progress"`
}

/* --- get_reports 報告結構 --- */

type getReportsResponse struct {
	XMLName xml.Name    `xml:"get_reports_response"`
	Results []gmpResult `xml:"report>report>results>result"`
}

type gmpResult struct {
	ID          string  `xml:"id,attr"`
	Name        string  `xml:"name"`
	Host        gmpText `xml:"host"`
	Port        string  `xml:"port"`
	NVT         gmpNVT  `xml:"nvt"`
	Threat      string  `xml:"threat"`
	Severity    string  `xml:"severity"`
	Description string  `xml:"description"`
}

/* gmpText 取元素的文字節點 GMP host 元素含子元素 asset 只需其中的 IP 文字 */
type gmpText struct {
	Value string `xml:",chardata"`
}

type gmpNVT struct {
	OID      string   `xml:"oid,attr"`
	Name     string   `xml:"name"`
	Family   string   `xml:"family"`
	CVSSBase string   `xml:"cvss_base"`
	Refs     []gmpRef `xml:"refs>ref"`
}

type gmpRef struct {
	Type string `xml:"type,attr"`
	ID   string `xml:"id,attr"`
}

/*
	Parse 將 GMP get_reports XML 轉為統一 Finding

每個 result 一筆 finding severity 優先取 CVSS 分數 為 0 時退回 threat 文字
CVE 參照入 References port 取 proto 前的埠號 套用 VA fingerprint engine + rule_id + host + port
*/
func (s *Scanner) Parse(raw []byte) ([]model.Finding, error) {
	if len(raw) == 0 {
		return []model.Finding{}, nil
	}

	var resp getReportsResponse
	if err := xml.Unmarshal(raw, &resp); err != nil {
		return nil, fmt.Errorf("openvas GMP 報告解析失敗: %w", err)
	}

	findings := make([]model.Finding, 0, len(resp.Results))
	for _, r := range resp.Results {
		host := strings.TrimSpace(r.Host.Value)
		port := portNumber(r.Port)

		f := model.Finding{
			Engine:           engineName,
			Category:         model.CategoryVA,
			RuleID:           r.NVT.OID,
			Title:            titleOf(r),
			Description:      strings.TrimSpace(r.Description),
			Severity:         severityOf(r),
			Host:             host,
			Port:             port,
			UniqueIDFromTool: r.NVT.OID + ":" + host + ":" + port,
		}

		if score, ok := parseFloat(r.NVT.CVSSBase); ok && score > 0 {
			f.CVSSScore = &score
		}
		if refs := cveRefs(r.NVT.Refs); len(refs) > 0 {
			f.References = refs
		}

		f.HashCode = core.Fingerprint(f)
		findings = append(findings, f)
	}

	return findings, nil
}

/* titleOf 取 result 顯示標題 優先 result name 退回 NVT name */
func titleOf(r gmpResult) string {
	if r.Name != "" {
		return r.Name
	}
	return r.NVT.Name
}

/*
	severityOf 決定 finding 嚴重度

優先以 severity CVSS 分數換算 分數 <=0 時退回 threat 文字 Log 視為 UNKNOWN
*/
func severityOf(r gmpResult) model.Severity {
	if score, ok := parseFloat(r.Severity); ok && score > 0 {
		return core.SeverityFromCVSS(score)
	}
	switch strings.ToLower(r.Threat) {
	case "high":
		return model.SeverityHigh
	case "medium":
		return model.SeverityMedium
	case "low":
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}

/* portNumber 取 GMP port 的埠號 443/tcp → 443 general/tcp 等無埠號者回原值 */
func portNumber(port string) string {
	if i := strings.Index(port, "/"); i >= 0 {
		head := port[:i]
		if _, err := strconv.Atoi(head); err == nil {
			return head
		}
		return port
	}
	return port
}

/* cveRefs 從 NVT refs 抽出 CVE 編號清單 */
func cveRefs(refs []gmpRef) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		if strings.EqualFold(r.Type, "cve") && r.ID != "" {
			out = append(out, r.ID)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

/* parseFloat 解析浮點字串 空或非數字回 false */
func parseFloat(s string) (float64, bool) {
	v, err := strconv.ParseFloat(strings.TrimSpace(s), 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

/* --- GMP 呼叫通道 --- */

/* gmp 為 GMP 指令執行通道 抽象化便於測試 生產以 docker compose exec 走容器內 gvm-cli */
type gmp interface {
	run(ctx context.Context, xmlCmd string) ([]byte, error)
}

/* dockerGMP 以 docker compose exec 呼叫容器內 gvm-cli 走 GMP socket */
type dockerGMP struct {
	user     string
	password string
}

/*
	newDockerGMP 建 docker GMP 通道 帳密取自環境變數

VIGILA_OPENVAS_USER / VIGILA_OPENVAS_PASSWORD 未設時用 immauss/openvas 預設 admin/admin
*/
func newDockerGMP() *dockerGMP {
	user := os.Getenv("VIGILA_OPENVAS_USER")
	if user == "" {
		user = "admin"
	}
	pw := os.Getenv("VIGILA_OPENVAS_PASSWORD")
	if pw == "" {
		pw = "admin"
	}
	return &dockerGMP{user: user, password: pw}
}

/*
	run 以 docker compose exec 在 openvas 容器內執行 gvm-cli socket 指令

--profile openvas 確保 service 啟用 -T 關閉 TTY 讓 stdout 可捕獲
*/
func (d *dockerGMP) run(ctx context.Context, xmlCmd string) ([]byte, error) {
	args := []string{
		"compose", "--profile", engineName, "exec", "-T", engineName,
		"gvm-cli", "--gmp-username", d.user, "--gmp-password", d.password,
		"socket", "--socketpath", gmpSocketPath,
		"--xml", xmlCmd,
	}
	res, err := scanner.DefaultRun(ctx, "docker", args)
	if err != nil {
		return nil, err
	}
	return res.RawOutput, nil
}
