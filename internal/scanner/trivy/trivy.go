// Package trivy 為 Trivy SCA 引擎 adapter
package trivy

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

const binaryName = "trivy"

/* Scanner 為 Trivy adapter 實作 */
type Scanner struct{}

func init() { scanner.Register(&Scanner{}) }

func (s *Scanner) Name() string             { return binaryName }
func (s *Scanner) Category() model.Category { return model.CategorySCA }
func (s *Scanner) Binary() string           { return binaryName }
func (s *Scanner) VersionArgs() []string    { return []string{"--version"} }

/* TargetKinds 目前以 trivy fs 掃描本機路徑 未來若支援 image 再擴充 */
func (s *Scanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetPath}
}

/* InstallHint trivy 安裝指引 */
func (s *Scanner) InstallHint() scanner.InstallHint {
	return scanner.InstallHint{
		DocsURL: "https://trivy.dev/latest/getting-started/installation/",
		Command: "brew install trivy",
	}
}

/* CheckInstalled 確認 trivy 已安裝 */
func (s *Scanner) CheckInstalled() error {
	return scanner.CheckBinary(binaryName)
}

/*
	BuildCommand 組 trivy 掃描指令

用 --exit-code 0 簡化判讀 即使有 finding 也回 0
--scanners vuln 只掃漏洞 加速
*/
func (s *Scanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	args := []string{
		"fs",
		"--scanners", "vuln",
		"--format", "json",
		"--exit-code", "0",
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

/* ExitCodeIsFindings 用 --exit-code 0 後恆回 false 執行成功即 0 */
func (s *Scanner) ExitCodeIsFindings(code int) bool {
	return false
}

/* trivyOutput 為 trivy JSON 輸出結構 */
type trivyOutput struct {
	Results []trivyResult `json:"Results"`
}

type trivyResult struct {
	Target          string               `json:"Target"`
	Vulnerabilities []trivyVulnerability `json:"Vulnerabilities"`
}

type trivyVulnerability struct {
	VulnerabilityID  string               `json:"VulnerabilityID"`
	PkgName          string               `json:"PkgName"`
	InstalledVersion string               `json:"InstalledVersion"`
	FixedVersion     string               `json:"FixedVersion"`
	Severity         string               `json:"Severity"`
	CVSS             map[string]trivyCVSS `json:"CVSS"`
	CweIDs           []string             `json:"CweIDs"`
	Title            string               `json:"Title"`
	Description      string               `json:"Description"`
	References       []string             `json:"References"`
	PrimaryURL       string               `json:"PrimaryURL"`
}

type trivyCVSS struct {
	V3Vector string  `json:"V3Vector"`
	V3Score  float64 `json:"V3Score"`
}

/*
	Parse 將 trivy JSON 轉為統一 Finding

CVE 同時作 RuleID 與 UniqueIDFromTool
套用 SCA fingerprint engine + cve + pkg + version
*/
func (s *Scanner) Parse(raw []byte) ([]model.Finding, error) {
	var out trivyOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("trivy JSON 解析失敗: %w", err)
	}

	findings := make([]model.Finding, 0)
	for _, res := range out.Results {
		for _, vuln := range res.Vulnerabilities {
			f := model.Finding{
				Engine:           binaryName,
				Category:         model.CategorySCA,
				RuleID:           vuln.VulnerabilityID,
				Title:            vuln.Title,
				Description:      vuln.Description,
				Severity:         core.NormalizeSeverity(vuln.Severity),
				PkgName:          vuln.PkgName,
				InstalledVersion: vuln.InstalledVersion,
				FixedVersion:     vuln.FixedVersion,
				UniqueIDFromTool: vuln.VulnerabilityID,
			}

			if len(vuln.CweIDs) > 0 {
				f.CWE = vuln.CweIDs[0]
			}

			/* CVSS 取 nvd 來源為主 */
			if cvss, ok := vuln.CVSS["nvd"]; ok && cvss.V3Score > 0 {
				score := cvss.V3Score
				f.CVSSScore = &score
				f.CVSSVector = cvss.V3Vector
			}

			refs := vuln.References
			if vuln.PrimaryURL != "" {
				refs = append(refs, vuln.PrimaryURL)
			}
			if len(refs) > 0 {
				f.References = refs
			}

			f.HashCode = core.Fingerprint(f)
			findings = append(findings, f)
		}
	}

	return findings, nil
}
