// Package nuclei 為 Nuclei DAST 引擎 adapter
//
// Nuclei 是 YAML template 驅動的網頁漏洞掃描器 9000+ 內建 templates
// target 為 URL 如 http://testphp.vulnweb.com
// 輸出為 NDJSON 每行一個 finding
//
// 授權 MIT
package nuclei

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

const binaryName = "nuclei"

/* Scanner 為 Nuclei adapter 實作 */
type Scanner struct{}

func init() { scanner.Register(&Scanner{}) }

func (s *Scanner) Name() string             { return binaryName }
func (s *Scanner) Category() model.Category { return model.CategoryDAST }
func (s *Scanner) Binary() string           { return binaryName }

/* TargetKinds nuclei 以 -u 指定完整網址 只吃 URL */
func (s *Scanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetURL}
}

/* CheckInstalled 確認 nuclei 已安裝 */
func (s *Scanner) CheckInstalled() error {
	return scanner.CheckBinary(binaryName)
}

/*
	BuildCommand 組 nuclei 掃描指令

-u <target> 指定目標 URL
-json 輸出 NDJSON 每行一個結果
-silent 只輸出結果 不含 banner
-nc 不檢查更新 避免網路等待
*/
func (s *Scanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	args := []string{
		"-u", target,
		"-json",
		"-silent",
		"-nc",
	}
	args = append(args, opts.ExtraArgs...)
	return binaryName, args
}

/* Run 執行掃描 用共用 subprocess 實作 stdout 即 NDJSON */
func (s *Scanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	binary, args := s.BuildCommand(target, opts)
	return scanner.DefaultRun(ctx, binary, args)
}

/* ExitCodeIsFindings nuclei 預設 exit 0 不論有無 finding */
func (s *Scanner) ExitCodeIsFindings(code int) bool {
	return false
}

/*
	nucleiResult 為單一 NDJSON 行的結構

matched-url 為觸發 template 的完整 URL
matched-at 為觸發位置 通常是 URL 或 URL 加片段
info.severity 為 template 定義的嚴重度 info low medium high critical
*/
type nucleiResult struct {
	TemplateID  string     `json:"template-id"`
	Info        nucleiInfo `json:"info"`
	MatchedURL  string     `json:"matched-url"`
	MatchedAt   string     `json:"matched-at"`
	Type        string     `json:"type"`
	Host        string     `json:"host"`
	CurlCommand string     `json:"curl-command"`
	IP          string     `json:"ip"`
}

type nucleiInfo struct {
	Name        string   `json:"name"`
	Severity    string   `json:"severity"`
	Description string   `json:"description"`
	Tags        string   `json:"tags"`
	Reference   []string `json:"reference"`
}

/*
	Parse 將 nuclei NDJSON 轉為統一 Finding

逐行解析 template-id 作 RuleID 與 UniqueIDFromTool
matched-url 作 URL 若為空回退用 matched-at
severity 用 NormalizeSeverity nuclei 的 info low medium high critical 都已涵蓋
套用 DAST fingerprint engine + rule_id + url
*/
func (s *Scanner) Parse(raw []byte) ([]model.Finding, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []model.Finding{}, nil
	}

	findings := make([]model.Finding, 0)
	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}

		var r nucleiResult
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("nuclei 第 %d 行 JSON 解析失敗: %w", lineNum, err)
		}

		/* 無 template-id 視為雜訊 跳過 */
		if r.TemplateID == "" {
			continue
		}

		/* matched-url 為主 matched-at 為輔 */
		matchedURL := r.MatchedURL
		if matchedURL == "" {
			matchedURL = r.MatchedAt
		}

		f := model.Finding{
			Engine:           binaryName,
			Category:         model.CategoryDAST,
			RuleID:           r.TemplateID,
			Title:            r.Info.Name,
			Description:      r.Info.Description,
			Severity:         core.NormalizeSeverity(r.Info.Severity),
			URL:              matchedURL,
			Host:             r.Host,
			Snippet:          r.CurlCommand,
			UniqueIDFromTool: r.TemplateID,
		}

		if r.Type != "" {
			f.Method = strings.ToUpper(r.Type)
		}

		if len(r.Info.Reference) > 0 {
			f.References = r.Info.Reference
		}

		f.HashCode = core.Fingerprint(f)
		findings = append(findings, f)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("nuclei NDJSON 讀取失敗: %w", err)
	}

	return findings, nil
}
