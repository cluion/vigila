// Package semgrep 為 Semgrep SAST 引擎 adapter
package semgrep

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

const (
	binaryName = "semgrep"
)

/* Scanner 為 Semgrep adapter 實作 */
type Scanner struct{}

func init() { scanner.Register(&Scanner{}) }

func (s *Scanner) Name() string             { return binaryName }
func (s *Scanner) Category() model.Category { return model.CategorySAST }
func (s *Scanner) Binary() string           { return binaryName }

/* TargetKinds semgrep 掃描原始碼 只吃本機路徑 */
func (s *Scanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetPath}
}

/* CheckInstalled 確認 semgrep 已安裝 */
func (s *Scanner) CheckInstalled() error {
	return scanner.CheckBinary(binaryName)
}

/*
	BuildCommand 組 semgrep 掃描指令

使用 p/default 規則集 預設離線友善 metrics=off 關閉遙測
*/
func (s *Scanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	config := opts.Config
	if config == "" {
		config = "p/default"
	}
	args := []string{
		"scan",
		"--config", config,
		"--json",
		"--metrics=off",
		"--quiet",
	}
	args = append(args, opts.ExtraArgs...)
	args = append(args, target)
	return binaryName, args
}

/* Run 執行掃描 用共用 subprocess 實作 */
func (s *Scanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	binary, args := s.BuildCommand(target, opts)
	return scanner.DefaultRun(ctx, binary, args)
}

/* ExitCodeIsFindings semgrep 有 finding 時 exit 非 0 視為正常發現 */
func (s *Scanner) ExitCodeIsFindings(code int) bool {
	return code == 1
}

/* semgrepOutput 為 semgrep JSON 輸出結構 */
type semgrepOutput struct {
	Results []semgrepResult `json:"results"`
}

type semgrepResult struct {
	CheckID string       `json:"check_id"`
	Path    string       `json:"path"`
	Start   semgrepPos   `json:"start"`
	End     semgrepPos   `json:"end"`
	Extra   semgrepExtra `json:"extra"`
}

type semgrepPos struct {
	Line   int `json:"line"`
	Col    int `json:"col"`
	Offset int `json:"offset"`
}

type semgrepExtra struct {
	Message     string      `json:"message"`
	Severity    string      `json:"severity"`
	Fingerprint string      `json:"fingerprint"`
	Lines       string      `json:"lines"`
	Metadata    semgrepMeta `json:"metadata"`
}

type semgrepMeta struct {
	Cwe        []string `json:"cwe"`
	References []string `json:"references"`
}

/*
	Parse 將 semgrep JSON 轉為統一 Finding

fingerprint 離線 OSS 可能為空 由 core.Fingerprint 算 hash 作 fallback
*/
func (s *Scanner) Parse(raw []byte) ([]model.Finding, error) {
	var out semgrepOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("semgrep JSON 解析失敗: %w", err)
	}

	findings := make([]model.Finding, 0, len(out.Results))
	for _, r := range out.Results {
		f := model.Finding{
			Engine:           binaryName,
			Category:         model.CategorySAST,
			RuleID:           r.CheckID,
			Title:            r.Extra.Message,
			Description:      r.Extra.Message,
			Severity:         core.NormalizeSeverity(r.Extra.Severity),
			FilePath:         r.Path,
			Snippet:          r.Extra.Lines,
			UniqueIDFromTool: r.Extra.Fingerprint,
		}

		startLine := int64(r.Start.Line)
		endLine := int64(r.End.Line)
		startCol := int64(r.Start.Col)
		endCol := int64(r.End.Col)
		f.StartLine = &startLine
		f.EndLine = &endLine
		f.StartCol = &startCol
		f.EndCol = &endCol

		if len(r.Extra.Metadata.Cwe) > 0 {
			f.CWE = parseCWE(r.Extra.Metadata.Cwe[0])
		}
		if len(r.Extra.Metadata.References) > 0 {
			f.References = r.Extra.Metadata.References
		}

		f.HashCode = core.Fingerprint(f)
		findings = append(findings, f)
	}

	return findings, nil
}

/* parseCWE 從 CWE 字串取出編號 如 CWE-78 */
func parseCWE(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, ":"); idx > 0 {
		s = s[:idx]
	}
	return strings.TrimSpace(s)
}
