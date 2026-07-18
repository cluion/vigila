// Package checkov 為 Checkov IaC 引擎 adapter
//
// Checkov 為 Bridgecrew/Prisma 開源的 IaC 設定掃描器 涵蓋 Terraform Kubernetes
// Dockerfile CloudFormation 等 找基礎設施即程式碼的錯誤設定 為既有五類外的新類別
// pip 安裝 非單一 binary 故不支援 vigila engine install 由 InstallHint 指引 pip 安裝
package checkov

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

const binaryName = "checkov"

/* Scanner 為 Checkov adapter 實作 */
type Scanner struct{}

func init() { scanner.Register(&Scanner{}) }

func (s *Scanner) Name() string             { return binaryName }
func (s *Scanner) Category() model.Category { return model.CategoryIaC }
func (s *Scanner) Binary() string           { return binaryName }
func (s *Scanner) VersionArgs() []string    { return []string{"--version"} }

/* TargetKinds checkov 掃描本機路徑下的 IaC 設定檔 */
func (s *Scanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetPath}
}

/* InstallHint checkov 為 pip 套件 無 managed 安裝 */
func (s *Scanner) InstallHint() scanner.InstallHint {
	return scanner.InstallHint{
		DocsURL: "https://www.checkov.io/2.Basics/Installing%20Checkov.html",
		Command: "pip install checkov",
	}
}

/* CheckInstalled 確認 checkov 已安裝 */
func (s *Scanner) CheckInstalled() error {
	return scanner.CheckBinary(binaryName)
}

/*
	BuildCommand 組 checkov 掃描指令

-d 掃描目錄 -o json 輸出至 stdout --compact 去除程式碼片段 --quiet 只列失敗檢查
*/
func (s *Scanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	args := []string{"-d", target, "-o", "json", "--compact", "--quiet"}
	args = append(args, opts.ExtraArgs...)
	return binaryName, args
}

/* Run 執行掃描 stdout 即 JSON stderr 為 log 不影響解析 */
func (s *Scanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	binary, args := s.BuildCommand(target, opts)
	return scanner.RunEngine(ctx, s.Name(), target, binary, args)
}

/* ExitCodeIsFindings checkov 有失敗檢查時 exit 1 */
func (s *Scanner) ExitCodeIsFindings(code int) bool {
	return code == 1
}

/* checkovDoc 為 checkov 單一 check_type 的輸出 掃多框架時頂層為其陣列 */
type checkovDoc struct {
	CheckType string `json:"check_type"`
	Results   struct {
		FailedChecks []checkovCheck `json:"failed_checks"`
	} `json:"results"`
}

type checkovCheck struct {
	CheckID       string `json:"check_id"`
	CheckName     string `json:"check_name"`
	Severity      string `json:"severity"`
	FilePath      string `json:"file_path"`
	FileLineRange []int  `json:"file_line_range"`
	Resource      string `json:"resource"`
	Guideline     string `json:"guideline"`
}

/*
	Parse 將 checkov JSON 轉為統一 Finding

頂層可能是單一物件或多框架的陣列 兩者皆攤平各自的 failed_checks
CE 版多數 severity 為空 預設 MEDIUM IaC 錯誤設定值得關注但非最高危
*/
func (s *Scanner) Parse(raw []byte) ([]model.Finding, error) {
	docs, err := decodeCheckov(raw)
	if err != nil {
		return nil, fmt.Errorf("checkov JSON 解析失敗: %w", err)
	}

	findings := make([]model.Finding, 0)
	for _, doc := range docs {
		for _, c := range doc.Results.FailedChecks {
			title := c.CheckName
			if title == "" {
				title = c.CheckID
			}
			f := model.Finding{
				Engine:           binaryName,
				Category:         model.CategoryIaC,
				RuleID:           c.CheckID,
				Title:            title,
				Description:      c.CheckName,
				Severity:         iacSeverity(c.Severity),
				FilePath:         c.FilePath,
				UniqueIDFromTool: c.CheckID + ":" + c.Resource,
			}

			if len(c.FileLineRange) >= 1 {
				start := int64(c.FileLineRange[0])
				f.StartLine = &start
			}
			if len(c.FileLineRange) >= 2 {
				end := int64(c.FileLineRange[1])
				f.EndLine = &end
			}
			if c.Guideline != "" {
				f.References = []string{c.Guideline}
			}

			f.HashCode = core.Fingerprint(f)
			findings = append(findings, f)
		}
	}
	return findings, nil
}

/*
	decodeCheckov 相容 checkov 頂層為單一物件或陣列的兩種輸出

掃單一框架時為物件 掃含多種 IaC 的目錄時為陣列 以首個非空白字元判別
*/
func decodeCheckov(raw []byte) ([]checkovDoc, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) > 0 && trimmed[0] == '[' {
		var docs []checkovDoc
		if err := json.Unmarshal(raw, &docs); err != nil {
			return nil, err
		}
		return docs, nil
	}
	var doc checkovDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return []checkovDoc{doc}, nil
}

/* iacSeverity checkov CE 常無 severity 空值預設 MEDIUM 有值則正規化 */
func iacSeverity(s string) model.Severity {
	if s == "" {
		return model.SeverityMedium
	}
	return core.NormalizeSeverity(s)
}
