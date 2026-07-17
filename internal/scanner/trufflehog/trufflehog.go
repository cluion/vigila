// Package trufflehog 為 TruffleHog Secret 引擎 adapter
//
// TruffleHog 是驗證式 secret 掃描器 與既有 Gitleaks 互補
// Gitleaks 為樣式匹配 誤報較多
// TruffleHog 真的拿 key 去 API 測試 回傳 Verified true false
// 只收 Verified true 活密鑰 一律標為 CRITICAL
//
// 授權 TruffleHog v3 起為 AGPL-3.0
// Vigila 以 subprocess 呼叫 不連結其程式碼 與既有 Semgrep Trivy 同為外部 binary
// 不影響 Vigila 本身的 MIT 授權
package trufflehog

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

const binaryName = "trufflehog"

/* Scanner 為 TruffleHog adapter 實作 */
type Scanner struct{}

func init() { scanner.Register(&Scanner{}) }

func (s *Scanner) Name() string             { return binaryName }
func (s *Scanner) Category() model.Category { return model.CategorySecret }
func (s *Scanner) Binary() string           { return binaryName }

/* TargetKinds 以 filesystem 模式掃描本機路徑 只吃路徑 */
func (s *Scanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetPath}
}

/* CheckInstalled 確認 trufflehog 已安裝 */
func (s *Scanner) CheckInstalled() error {
	return scanner.CheckBinary(binaryName)
}

/*
	BuildCommand 組 trufflehog 掃描指令

filesystem <target> 掃檔案系統目錄
--json 輸出 NDJSON 每行一個結果
--results=verified 只輸出已驗證結果 過濾 unknown plausible
*/
func (s *Scanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	args := []string{
		"filesystem",
		target,
		"--json",
		"--results=verified",
	}
	args = append(args, opts.ExtraArgs...)
	return binaryName, args
}

/* Run 執行掃描 用共用 subprocess 實作 stdout 即 NDJSON */
func (s *Scanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	binary, args := s.BuildCommand(target, opts)
	return scanner.DefaultRun(ctx, binary, args)
}

/* ExitCodeIsFindings 預設 exit 0 不論有無 finding */
func (s *Scanner) ExitCodeIsFindings(code int) bool {
	return false
}

/*
	trufflehogResult 為單一 NDJSON 行的結構

SourceMetadata.data 依來源不同有 filesystem git 等
Verified 為 true 才是活密鑰
Redacted 為已遮蔽的 secret 內容
*/
type trufflehogResult struct {
	SourceID       string                 `json:"SourceID"`
	SourceType     string                 `json:"SourceType"`
	SourceMetadata trufflehogSourceMeta   `json:"SourceMetadata"`
	DetectorName   string                 `json:"DetectorName"`
	DetectorType   string                 `json:"DetectorType"`
	Verified       bool                   `json:"Verified"`
	Raw            string                 `json:"Raw"`
	RawV2          string                 `json:"RawV2"`
	Redacted       string                 `json:"Redacted"`
	ExtraData      string                 `json:"ExtraData"`
	StructuredData map[string]interface{} `json:"StructuredData"`
}

type trufflehogSourceMeta struct {
	Data trufflehogSourceData `json:"data"`
}

type trufflehogSourceData struct {
	Filesystem *trufflehogFilesystem `json:"filesystem,omitempty"`
	Git        *trufflehogGit        `json:"git,omitempty"`
}

type trufflehogFilesystem struct {
	File string `json:"file"`
	Line int64  `json:"line"`
}

type trufflehogGit struct {
	Commit     string `json:"commit"`
	File       string `json:"file"`
	Email      string `json:"email"`
	Repository string `json:"repository"`
	Timestamp  string `json:"timestamp"`
	Line       int64  `json:"line"`
}

/*
	Parse 將 trufflehog NDJSON 轉為統一 Finding

逐行解析 只收 Verified true 雙保險 配合 --results=verified
活密鑰一律 CRITICAL 已驗證 能登入 最高危
套用 Secret fingerprint engine + rule_id + file_path + start_line
*/
func (s *Scanner) Parse(raw []byte) ([]model.Finding, error) {
	/* 空輸入代表沒有發現 */
	if len(bytes.TrimSpace(raw)) == 0 {
		return []model.Finding{}, nil
	}

	findings := make([]model.Finding, 0)
	sc := bufio.NewScanner(bytes.NewReader(raw))
	/* secret 內容可能很長 提高緩衝上限 */
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)

	lineNum := 0
	for sc.Scan() {
		lineNum++
		line := bytes.TrimSpace(sc.Bytes())
		if len(line) == 0 {
			continue
		}

		var r trufflehogResult
		if err := json.Unmarshal(line, &r); err != nil {
			return nil, fmt.Errorf("trufflehog 第 %d 行 JSON 解析失敗: %w", lineNum, err)
		}

		/* 雙保險 只收 Verified true */
		if !r.Verified {
			continue
		}

		filePath, lineNo := extractLocation(&r)
		f := model.Finding{
			Engine:           binaryName,
			Category:         model.CategorySecret,
			RuleID:           r.DetectorName,
			Title:            r.DetectorName + " 已驗證的密鑰",
			Description:      fmt.Sprintf("TruffleHog 偵測到已驗證的 %s 密鑰 此密鑰確認為有效 仍在使用中", r.DetectorName),
			Severity:         model.SeverityCritical,
			FilePath:         filePath,
			Snippet:          r.Redacted,
			SecretType:       r.DetectorName,
			UniqueIDFromTool: buildUniqueID(&r, filePath, lineNo),
		}

		if lineNo > 0 {
			l := lineNo
			f.StartLine = &l
		}

		if r.ExtraData != "" {
			f.References = []string{r.ExtraData}
		}

		f.HashCode = core.Fingerprint(f)
		findings = append(findings, f)
	}

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("trufflehog NDJSON 讀取失敗: %w", err)
	}

	return findings, nil
}

/* extractLocation 從 SourceMetadata 取出檔案路徑與行號 */
func extractLocation(r *trufflehogResult) (string, int64) {
	if r.SourceMetadata.Data.Filesystem != nil {
		return r.SourceMetadata.Data.Filesystem.File, r.SourceMetadata.Data.Filesystem.Line
	}
	if r.SourceMetadata.Data.Git != nil {
		return r.SourceMetadata.Data.Git.File, r.SourceMetadata.Data.Git.Line
	}
	return "", 0
}

/* buildUniqueID 組 UniqueIDFromTool DetectorName FilePath line 三段 */
func buildUniqueID(r *trufflehogResult, filePath string, lineNo int64) string {
	parts := []string{r.DetectorName, filePath}
	if lineNo > 0 {
		parts = append(parts, fmt.Sprintf("%d", lineNo))
	}
	return strings.Join(parts, ":")
}
