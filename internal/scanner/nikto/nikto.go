// Package nikto 為 Nikto 網頁伺服器掃描器 DAST adapter
//
// Nikto 對運行中的網頁伺服器做已知漏洞與設定缺陷偵測 target 為 URL
// 以 -Format json -output <檔> 產傳統 JSON 報告 報告只能寫檔故執行後讀回
// Nikto 為 Perl script 無單一 binary 需原生安裝或用官方 Docker image 見 InstallHint
//
// Nikto 本身不分級 findings 皆歸 LOW（多為設定提示與資訊洩漏）供人工複核升級
// 授權 GPL-2.0 Vigila 以 subprocess 呼叫不連結程式碼 不影響 MIT 授權
package nikto

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

const binaryName = "nikto"

/* Scanner 為 Nikto adapter 實作 */
type Scanner struct{}

func init() { scanner.Register(&Scanner{}) }

func (s *Scanner) Name() string             { return binaryName }
func (s *Scanner) Category() model.Category { return model.CategoryDAST }
func (s *Scanner) Binary() string           { return binaryName }
func (s *Scanner) VersionArgs() []string    { return []string{"-Version"} }

/* TargetKinds nikto 對完整網址掃描 只吃 URL */
func (s *Scanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetURL}
}

/* InstallHint nikto 安裝指引 docker 執行請用面板 Docker 開關 */
func (s *Scanner) InstallHint() scanner.InstallHint {
	return scanner.InstallHint{
		DocsURL: "https://github.com/sullo/nikto/wiki",
		Command: "brew install nikto",
	}
}

/* CheckInstalled 確認 nikto 可用 系統 nikto 或已勾選 nikto docker profile 皆可 */
func (s *Scanner) CheckInstalled() error {
	return scanner.CheckBinary(binaryName)
}

/*
	BuildCommand 組 nikto 掃描指令

-h <target> 指定目標 URL
-Format json 明確指定 JSON 格式 不依副檔名推導
-output <檔> 報告寫檔 執行後讀回
-nointeractive 關閉互動避免卡在提示
*/
func (s *Scanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	args := []string{
		"-h", target,
		"-Format", "json",
		"-output", reportPath(),
		"-nointeractive",
	}
	args = append(args, opts.ExtraArgs...)
	return binaryName, args
}

/* reportPath 為每次掃描的暫存 report 檔路徑 */
func reportPath() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("vigila-nikto-%d.json", time.Now().UnixNano()))
}

/*
	Run 執行掃描 依來源分流

系統來源用本機 nikto 報告寫暫存檔後讀回再刪除 docker 來源用官方 image
掛暫存輸出目錄到容器 報告寫入其中執行後讀回 兩者報告格式相同由 Parse 共用
*/
func (s *Scanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	if scanner.ResolveSourceFor(s.Name(), binaryName) == scanner.SourceDocker {
		return s.runDocker(ctx, target, opts)
	}
	return s.runSystem(ctx, target, opts)
}

/* runSystem 用本機 nikto 執行 報告寫暫存檔後讀回再刪除 與 zap 同模式 */
func (s *Scanner) runSystem(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	binary, args := s.BuildCommand(target, opts)

	reportFile := ""
	for i, a := range args {
		if a == "-output" && i+1 < len(args) {
			reportFile = args[i+1]
			break
		}
	}

	res, err := scanner.DefaultRun(ctx, binary, args)
	if err != nil {
		if reportFile != "" {
			_ = os.Remove(reportFile)
		}
		return nil, err
	}

	if reportFile != "" {
		if raw, rerr := os.ReadFile(reportFile); rerr == nil { // #nosec G304 -- reportFile 為本程式產生的暫存路徑
			res.RawOutput = raw
		}
		_ = os.Remove(reportFile)
	}
	return res, nil
}

/* 容器內報告目錄 掛暫存輸出目錄至此 nikto -output 相對於此 */
const containerOut = "/output"

/*
	runDocker 用官方 image 執行 nikto

nikto 只需對 URL 發請求 不掛載目標 僅掛暫存輸出目錄讓報告可讀回
compose --profile nikto 對應 docker-compose.yml 的 nikto 服務 與勾選機制一致
*/
func (s *Scanner) runDocker(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	outDir, err := os.MkdirTemp("", "vigila-nikto-*")
	if err != nil {
		return nil, fmt.Errorf("建立 nikto 輸出暫存目錄失敗: %w", err)
	}
	defer func() { _ = os.RemoveAll(outDir) }()
	/* 容器內 nikto 使用者需寫入報告 暫存目錄用後即刪 world 權限限於臨時目錄 */
	_ = os.Chmod(outDir, 0o777) // #nosec G302

	const reportName = "report.json"
	args := []string{
		"compose", "--profile", "nikto", "run", "--rm",
		"-v", outDir + ":" + containerOut + ":rw",
		"nikto",
		"-h", target,
		"-Format", "json",
		"-output", containerOut + "/" + reportName,
		"-nointeractive",
	}
	args = append(args, opts.ExtraArgs...)

	res, err := scanner.DefaultRun(ctx, "docker", args)
	if err != nil {
		return nil, err
	}
	if raw, rerr := os.ReadFile(filepath.Join(outDir, reportName)); rerr == nil { // #nosec G304 -- outDir 為本程式產生的暫存目錄
		res.RawOutput = raw
	}
	return res, nil
}

/* ExitCodeIsFindings nikto 不以 exit code 表達有無發現 一律回 false */
func (s *Scanner) ExitCodeIsFindings(code int) bool {
	return false
}

/* niktoHost 為 nikto JSON 報告的單一主機區塊 */
type niktoHost struct {
	Host            string          `json:"host"`
	IP              string          `json:"ip"`
	Port            string          `json:"port"`
	Vulnerabilities []niktoVulnItem `json:"vulnerabilities"`
}

/*
	niktoVulnItem 為單一發現 nikto 不提供 severity

id 為 nikto 測試項編號 msg 為描述 url 為相對路徑 references 為單一連結字串（可為空）
*/
type niktoVulnItem struct {
	ID         string `json:"id"`
	Method     string `json:"method"`
	URL        string `json:"url"`
	Msg        string `json:"msg"`
	References string `json:"references"`
	OSVDB      string `json:"OSVDB"`
}

/*
	Parse 將 nikto JSON 報告轉為統一 Finding

相容陣列（nikto 2.5.0）與單一物件兩種頂層形狀
每個 vulnerability 一筆 finding msg 作 Title host+url 組合為 URL
nikto 無 severity 一律 LOW 供人工複核 套用 DAST fingerprint engine + rule_id + url
*/
func (s *Scanner) Parse(raw []byte) ([]model.Finding, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return []model.Finding{}, nil
	}

	hosts, err := decodeHosts(trimmed)
	if err != nil {
		return nil, err
	}

	findings := make([]model.Finding, 0)
	for _, h := range hosts {
		for _, v := range h.Vulnerabilities {
			/* 無測試項編號視為雜訊 跳過 */
			if strings.TrimSpace(v.ID) == "" {
				continue
			}

			f := model.Finding{
				Engine:           binaryName,
				Category:         model.CategoryDAST,
				RuleID:           v.ID,
				Title:            v.Msg,
				Severity:         model.SeverityLow,
				URL:              joinURL(h.Host, h.Port, v.URL),
				Host:             h.Host,
				Port:             h.Port,
				Method:           strings.ToUpper(v.Method),
				UniqueIDFromTool: v.ID + ":" + v.URL,
			}

			if refs := splitRefs(v.References); len(refs) > 0 {
				f.References = refs
			}

			f.HashCode = core.Fingerprint(f)
			findings = append(findings, f)
		}
	}

	return findings, nil
}

/* decodeHosts 依頂層形狀解出主機清單 [ 為陣列 { 為單一物件 */
func decodeHosts(trimmed []byte) ([]niktoHost, error) {
	if trimmed[0] == '[' {
		var hosts []niktoHost
		if err := json.Unmarshal(trimmed, &hosts); err != nil {
			return nil, fmt.Errorf("nikto JSON 陣列解析失敗: %w", err)
		}
		return hosts, nil
	}

	var h niktoHost
	if err := json.Unmarshal(trimmed, &h); err != nil {
		return nil, fmt.Errorf("nikto JSON 解析失敗: %w", err)
	}
	return []niktoHost{h}, nil
}

/*
	joinURL 由主機 埠 與相對路徑組出可讀 URL

nikto 報告不含 scheme 依常見埠推導 443 用 https 其餘 http 僅供顯示與去重
*/
func joinURL(host, port, path string) string {
	if host == "" {
		return path
	}
	scheme := "http"
	if port == "443" {
		scheme = "https"
	}
	base := scheme + "://" + host
	if port != "" && port != "80" && port != "443" {
		base += ":" + port
	}
	if path == "" {
		return base
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return base + path
}

/* splitRefs 把 references 字串切成連結清單 nikto 以空白分隔 空字串回 nil */
func splitRefs(refs string) []string {
	fields := strings.Fields(refs)
	if len(fields) == 0 {
		return nil
	}
	return fields
}
