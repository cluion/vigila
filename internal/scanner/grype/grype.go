// Package grype 為 Grype SCA 引擎 adapter
//
// Grype 為 Anchore 開源的漏洞掃描器 與既有 Trivy 互補
// Trivy 自帶 DB Grype 用 Anchore DB 兩者 CVE 覆蓋不同 交叉掃描補漏
// Fingerprint 含 engine 欄位 同套件兩引擎不會碰撞 使用者可比對差異
package grype

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

const binaryName = "grype"

/* Scanner 為 Grype adapter 實作 */
type Scanner struct{}

func init() { scanner.Register(&Scanner{}) }

func (s *Scanner) Name() string             { return binaryName }
func (s *Scanner) Category() model.Category { return model.CategorySCA }
func (s *Scanner) Binary() string           { return binaryName }

/* TargetKinds 目前以 dir: 前綴掃描本機路徑 未來若支援 image 再擴充 */
func (s *Scanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetPath}
}

/* CheckInstalled 確認 grype 已安裝 */
func (s *Scanner) CheckInstalled() error {
	return scanner.CheckBinary(binaryName)
}

/*
	BuildCommand 組 grype 掃描指令

dir:<target> 掃檔案系統目錄 與 Trivy fs 對應
預設 exit 0 即使有 finding 簡化判讀
*/
func (s *Scanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	args := []string{
		"dir:" + target,
		"-o", "json",
		"--quiet",
	}
	args = append(args, opts.ExtraArgs...)
	return binaryName, args
}

/* Run 執行掃描 用共用 subprocess 實作 stdout 即 JSON */
func (s *Scanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	binary, args := s.BuildCommand(target, opts)
	return scanner.DefaultRun(ctx, binary, args)
}

/* ExitCodeIsFindings 預設 exit 0 不論有無 finding */
func (s *Scanner) ExitCodeIsFindings(code int) bool {
	return false
}

/* grypeOutput 為 grype JSON 輸出結構 */
type grypeOutput struct {
	Matches []grypeMatch `json:"matches"`
}

type grypeMatch struct {
	Vulnerability grypeVulnerability `json:"vulnerability"`
	Artifact      grypeArtifact      `json:"artifact"`
}

type grypeVulnerability struct {
	ID          string     `json:"id"`
	Severity    string     `json:"severity"`
	Description string     `json:"description"`
	Fix         grypeFix   `json:"fix"`
	CVSS        []grypeCVS `json:"cvss"`
	URLs        []string   `json:"urls"`
}

type grypeFix struct {
	Versions []string `json:"versions"`
}

type grypeCVS struct {
	Source  string       `json:"source"`
	Metrics grypeMetrics `json:"metrics"`
	Vector  string       `json:"vector"`
}

type grypeMetrics struct {
	BaseScore float64 `json:"baseScore"`
}

type grypeArtifact struct {
	Name      string          `json:"name"`
	Version   string          `json:"version"`
	Locations []grypeLocation `json:"locations"`
}

type grypeLocation struct {
	Path string `json:"path"`
}

/*
	Parse 將 grype JSON 轉為統一 Finding

CVE 同時作 RuleID 與 UniqueIDFromTool 一部分
CVSS 取 nvd 來源為主 與 Trivy 同
套用 SCA fingerprint engine + cve + pkg + version
*/
func (s *Scanner) Parse(raw []byte) ([]model.Finding, error) {
	var out grypeOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("grype JSON 解析失敗: %w", err)
	}

	findings := make([]model.Finding, 0, len(out.Matches))
	for _, m := range out.Matches {
		v := m.Vulnerability
		a := m.Artifact
		f := model.Finding{
			Engine:           binaryName,
			Category:         model.CategorySCA,
			RuleID:           v.ID,
			Title:            v.ID,
			Description:      v.Description,
			Severity:         core.NormalizeSeverity(v.Severity),
			PkgName:          a.Name,
			InstalledVersion: a.Version,
			FixedVersion:     strings.Join(v.Fix.Versions, ", "),
			UniqueIDFromTool: v.ID + ":" + a.Name,
		}

		if len(v.Fix.Versions) > 0 {
			f.FixedVersion = strings.Join(v.Fix.Versions, ", ")
		}

		/* CVSS 取 nvd 來源為主 */
		for _, c := range v.CVSS {
			if c.Source == "nvd" && c.Metrics.BaseScore > 0 {
				score := c.Metrics.BaseScore
				f.CVSSScore = &score
				f.CVSSVector = c.Vector
				break
			}
		}

		if len(v.URLs) > 0 {
			f.References = v.URLs
		}

		f.HashCode = core.Fingerprint(f)
		findings = append(findings, f)
	}

	return findings, nil
}
