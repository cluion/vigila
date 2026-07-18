// Package zap 為 OWASP ZAP DAST 引擎 adapter
//
// ZAP 為 OWASP 旗艦級動態掃描器 對運行中的網頁主動與被動掃描 target 為 URL
// 以 headless -cmd -quickurl 快速掃描輸出傳統 JSON 報告 報告只能寫檔故執行後讀回
// 非單一 binary 需原生安裝 zap.sh 或用官方 Docker image 見 InstallHint
package zap

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

const binaryName = "zap.sh"

/* Scanner 為 OWASP ZAP adapter 實作 */
type Scanner struct{}

func init() { scanner.Register(&Scanner{}) }

func (s *Scanner) Name() string             { return "zap" }
func (s *Scanner) Category() model.Category { return model.CategoryDAST }
func (s *Scanner) Binary() string           { return binaryName }
func (s *Scanner) VersionArgs() []string    { return []string{"-version"} }

/* TargetKinds ZAP 對完整網址發動動態掃描 只吃 URL */
func (s *Scanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetURL}
}

/* InstallHint ZAP 原生安裝或用官方 Docker image */
func (s *Scanner) InstallHint() scanner.InstallHint {
	return scanner.InstallHint{
		DocsURL: "https://www.zaproxy.org/download/",
		Command: "brew install --cask zap  # 或 docker pull ghcr.io/zaproxy/zaproxy:stable",
	}
}

/* CheckInstalled 確認 zap.sh 已安裝 */
func (s *Scanner) CheckInstalled() error {
	return scanner.CheckBinary(binaryName)
}

/*
	BuildCommand 組 ZAP headless 快速掃描指令

-cmd headless 命令列模式 -quickurl 目標 -quickout .json 輸出傳統 JSON 報告
-quickprogress 顯示進度 報告以副檔名決定格式 json 即 site alerts 結構
*/
func (s *Scanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	args := []string{
		"-cmd",
		"-quickurl", target,
		"-quickout", reportPath(),
		"-quickprogress",
	}
	args = append(args, opts.ExtraArgs...)
	return binaryName, args
}

/* reportPath 為每次掃描的暫存 report 檔路徑 */
func reportPath() string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("vigila-zap-%d.json", time.Now().UnixNano()))
}

/*
	Run 執行掃描 覆寫共用實作

ZAP 報告只能寫檔 執行後讀檔再刪除 與 gitleaks 同模式
*/
func (s *Scanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	binary, args := s.BuildCommand(target, opts)

	reportFile := ""
	for i, a := range args {
		if a == "-quickout" && i+1 < len(args) {
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
		if raw, rerr := os.ReadFile(reportFile); rerr == nil {
			res.RawOutput = raw
		}
		_ = os.Remove(reportFile)
	}
	return res, nil
}

/*
	ExitCodeIsFindings ZAP 不以 exit code 判定發現

baseline 有 warn 時回非零 findings 由報告內容決定 故一律回 false
*/
func (s *Scanner) ExitCodeIsFindings(code int) bool {
	return false
}

/* zapReport 為 ZAP 傳統 JSON 報告頂層 site 依掃描目標分組 */
type zapReport struct {
	Site []zapSite `json:"site"`
}

type zapSite struct {
	Name   string     `json:"@name"`
	Host   string     `json:"@host"`
	Alerts []zapAlert `json:"alerts"`
}

/*
	zapAlert 為一個警示 已按 alert 聚合 instances 為各觸發位置

riskcode 0 資訊 1 低 2 中 3 高 desc solution reference 皆為 HTML
*/
type zapAlert struct {
	PluginID  string        `json:"pluginid"`
	Alert     string        `json:"alert"`
	RiskCode  string        `json:"riskcode"`
	Desc      string        `json:"desc"`
	Solution  string        `json:"solution"`
	Reference string        `json:"reference"`
	CWEID     string        `json:"cweid"`
	Instances []zapInstance `json:"instances"`
}

type zapInstance struct {
	URI    string `json:"uri"`
	Method string `json:"method"`
	Param  string `json:"param"`
}

/*
	Parse 將 ZAP 傳統 JSON 報告轉為統一 Finding

每個 alert 一筆 finding URL 取首個 instance uri 無則退回 site 名
riskcode 換算 severity desc solution 去 HTML reference 抽出 URL 清單
套用 DAST fingerprint engine + rule_id + url
*/
func (s *Scanner) Parse(raw []byte) ([]model.Finding, error) {
	var report zapReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return nil, fmt.Errorf("ZAP JSON 解析失敗: %w", err)
	}

	findings := make([]model.Finding, 0)
	for _, site := range report.Site {
		for _, a := range site.Alerts {
			url := site.Name
			method := ""
			if len(a.Instances) > 0 {
				if a.Instances[0].URI != "" {
					url = a.Instances[0].URI
				}
				method = strings.ToUpper(a.Instances[0].Method)
			}

			f := model.Finding{
				Engine:           binaryName,
				Category:         model.CategoryDAST,
				RuleID:           a.PluginID,
				Title:            a.Alert,
				Description:      stripHTML(a.Desc),
				Severity:         riskSeverity(a.RiskCode),
				URL:              url,
				Host:             site.Host,
				Method:           method,
				CWE:              a.CWEID,
				UniqueIDFromTool: a.PluginID,
			}

			if refs := extractURLs(a.Reference); len(refs) > 0 {
				f.References = refs
			}

			f.HashCode = core.Fingerprint(f)
			findings = append(findings, f)
		}
	}
	return findings, nil
}

/*
	riskSeverity 把 ZAP riskcode 對應 5 級 severity

ZAP 無 critical 3 為最高 0 為資訊性歸 UNKNOWN
*/
func riskSeverity(code string) model.Severity {
	switch code {
	case "3":
		return model.SeverityHigh
	case "2":
		return model.SeverityMedium
	case "1":
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}

var (
	tagRe = regexp.MustCompile(`<[^>]*>`)
	wsRe  = regexp.MustCompile(`\s+`)
	urlRe = regexp.MustCompile(`https?://[^\s<>"]+`)
)

/* stripHTML 去除 HTML 標籤並收斂空白 供 desc solution 轉純文字 */
func stripHTML(s string) string {
	return strings.TrimSpace(wsRe.ReplaceAllString(tagRe.ReplaceAllString(s, " "), " "))
}

/* extractURLs 從 HTML reference 抽出所有 http(s) 連結 */
func extractURLs(s string) []string {
	return urlRe.FindAllString(s, -1)
}
