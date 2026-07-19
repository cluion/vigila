// Package gitleaks 為 Gitleaks Secret 引擎 adapter
package gitleaks

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

const binaryName = "gitleaks"

/* criticalRules 為高風險 secret 規則 映射為 CRITICAL */
var criticalRules = []string{
	"aws-access-token",
	"github-pat",
	"gitlab-pat",
	"private-key",
	"jwt",
	"slack-token",
	"google-api-key",
	"stripe",
}

/* Scanner 為 Gitleaks adapter 實作 */
type Scanner struct{}

func init() { scanner.Register(&Scanner{}) }

func (s *Scanner) Name() string             { return binaryName }
func (s *Scanner) Category() model.Category { return model.CategorySecret }
func (s *Scanner) Binary() string           { return binaryName }
func (s *Scanner) VersionArgs() []string    { return []string{"version"} }

/* TargetKinds gitleaks 掃描本機目錄或 git repo 只吃路徑 */
func (s *Scanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetPath}
}

/* InstallHint gitleaks 安裝指引 */
func (s *Scanner) InstallHint() scanner.InstallHint {
	return scanner.InstallHint{
		DocsURL: "https://github.com/gitleaks/gitleaks#installing",
		Command: "vigila engine install gitleaks",
	}
}

/* CheckInstalled 確認 gitleaks 已安裝 */
func (s *Scanner) CheckInstalled() error {
	return scanner.CheckBinary(binaryName)
}

/*
	BuildCommand 組 gitleaks 掃描指令

關鍵 gitleaks 只能寫檔 不吐 stdout 故用暫存檔
用 dir 掃一般目錄 不需 git repo
*/
func (s *Scanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	args := []string{
		"dir",
		target,
		"--report-format", "json",
		"--report-path", reportPath(target),
		"--no-banner",
	}
	args = append(args, opts.ExtraArgs...)
	return binaryName, args
}

/* reportPath 為每次掃描的暫存 report 檔路徑 */
func reportPath(target string) string {
	return filepath.Join(os.TempDir(), fmt.Sprintf("vigila-gitleaks-%d.json", time.Now().UnixNano()))
}

/*
	Run 執行掃描 依來源分流

gitleaks report 只能寫檔 docker 來源掛目標與輸出目錄執行後讀回 系統來源寫暫存檔讀回
沒找到 secret 時 gitleaks 不寫 report 檔 視為空結果
*/
func (s *Scanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	if scanner.ResolveSourceFor(s.Name(), binaryName) == scanner.SourceDocker {
		return s.runDocker(ctx, target, opts)
	}
	return s.runSystem(ctx, target, opts)
}

/* runSystem 以本機 gitleaks 執行 report 寫暫存檔後讀回再刪除 */
func (s *Scanner) runSystem(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	binary, args := s.BuildCommand(target, opts)

	/* 找出 report-path 引數值 */
	reportFile := ""
	for i, a := range args {
		if a == "--report-path" && i+1 < len(args) {
			reportFile = args[i+1]
			break
		}
	}

	res, err := scanner.DefaultRun(ctx, binary, args)
	if err != nil {
		_ = os.Remove(reportFile)
		return nil, err
	}

	/* 讀取 report 檔內容作為 RawOutput 並刪除
	檔案不存在代表沒有發現 留空 RawOutput 即可 */
	if reportFile != "" {
		if raw, rerr := os.ReadFile(reportFile); rerr == nil {
			res.RawOutput = raw
		}
		_ = os.Remove(reportFile)
	}

	return res, nil
}

/*
	runDocker 以官方 image 執行 掛目標與暫存輸出目錄

報告寫入掛載的輸出目錄 執行後從主機端讀回 找不到報告代表無發現 留空
*/
func (s *Scanner) runDocker(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	abs, err := filepath.Abs(target)
	if err != nil {
		abs = target
	}
	/* 0o700 僅本人可存取 報告含密鑰明文 不可世界可讀 */
	outDir, err := os.MkdirTemp("", "vigila-gitleaks-*")
	if err != nil {
		return nil, fmt.Errorf("建立 gitleaks 輸出暫存目錄失敗: %w", err)
	}
	defer func() { _ = os.RemoveAll(outDir) }()

	/* 以主機使用者身分執行容器 使其能寫入 0o700 目錄 免用世界可寫目錄 unix 才有 uid */
	user := ""
	if uid := os.Getuid(); uid >= 0 {
		user = fmt.Sprintf("%d:%d", uid, os.Getgid())
	}

	report := filepath.Join(outDir, "report.json")
	args := []string{"dir", abs, "--report-format", "json", "--report-path", report, "--no-banner"}
	args = append(args, opts.ExtraArgs...)

	res, err := scanner.DefaultRun(ctx, "docker", scanner.DockerReportArgs(s.Name(), abs, outDir, user, args))
	if err != nil {
		return nil, err
	}
	if raw, rerr := os.ReadFile(report); rerr == nil {
		res.RawOutput = raw
	}
	return res, nil
}

/* ExitCodeIsFindings gitleaks 有 finding 回 1 視為正常發現 */
func (s *Scanner) ExitCodeIsFindings(code int) bool {
	return code == 1
}

/* gitleaksFinding 為 gitleaks JSON 輸出結構 頂層為 array */
type gitleaksFinding struct {
	RuleID      string   `json:"RuleID"`
	Description string   `json:"Description"`
	Secret      string   `json:"Secret"`
	Match       string   `json:"Match"`
	File        string   `json:"File"`
	StartLine   int      `json:"StartLine"`
	EndLine     int      `json:"EndLine"`
	StartColumn int      `json:"StartColumn"`
	EndColumn   int      `json:"EndColumn"`
	Entropy     float64  `json:"Entropy"`
	Fingerprint string   `json:"Fingerprint"`
	Tags        []string `json:"Tags"`
}

/*
	Parse 將 gitleaks JSON 轉為統一 Finding

gitleaks 無 severity 欄位 依 RuleID 自訂映射
Fingerprint 穩定可靠 直接作 UniqueIDFromTool
*/
func (s *Scanner) Parse(raw []byte) ([]model.Finding, error) {
	/* 空輸入代表沒有發現 gitleaks 沒找到 secret 時不寫 report 檔 */
	if len(bytes.TrimSpace(raw)) == 0 {
		return []model.Finding{}, nil
	}

	var findings []gitleaksFinding
	if err := json.Unmarshal(raw, &findings); err != nil {
		return nil, fmt.Errorf("gitleaks JSON 解析失敗: %w", err)
	}

	out := make([]model.Finding, 0, len(findings))
	for _, gf := range findings {
		f := model.Finding{
			Engine:           binaryName,
			Category:         model.CategorySecret,
			RuleID:           gf.RuleID,
			Title:            gf.Description,
			Description:      gf.Description,
			Severity:         mapSeverity(gf.RuleID),
			FilePath:         gf.File,
			Snippet:          maskSecret(gf.Match),
			SecretType:       gf.RuleID,
			UniqueIDFromTool: gf.Fingerprint,
		}

		startLine := int64(gf.StartLine)
		endLine := int64(gf.EndLine)
		startCol := int64(gf.StartColumn)
		endCol := int64(gf.EndColumn)
		f.StartLine = &startLine
		f.EndLine = &endLine
		f.StartCol = &startCol
		f.EndCol = &endCol

		if len(gf.Tags) > 0 {
			f.References = gf.Tags
		}

		f.HashCode = core.Fingerprint(f)
		out = append(out, f)
	}

	return out, nil
}

/*
	mapSeverity gitleaks 無 severity 依 RuleID 映射

token 與 key 類為 CRITICAL 其餘為 HIGH
*/
func mapSeverity(ruleID string) model.Severity {
	lower := strings.ToLower(ruleID)
	for _, cr := range criticalRules {
		if strings.Contains(lower, cr) {
			return model.SeverityCritical
		}
	}
	return model.SeverityHigh
}

/* maskSecret 遮蔽 secret 前後 只留中間少數字元 */
func maskSecret(s string) string {
	if len(s) <= 8 {
		return "****REDACTED****"
	}
	return s[:4] + "****REDACTED****" + s[len(s)-4:]
}
