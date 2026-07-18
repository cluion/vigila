// Package osvscanner 為 OSV-Scanner SCA 引擎 adapter
//
// OSV-Scanner 為 Google 開源 以 OSV.dev 漏洞資料庫比對依賴 涵蓋多生態系
// 與 Grype Trivy 資料來源不同 三者交叉掃描可補漏 fingerprint 含 engine 欄位不碰撞
// 直接發佈裸 binary 支援 vigila engine install osv-scanner 自動安裝
package osvscanner

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

const binaryName = "osv-scanner"

/* Scanner 為 OSV-Scanner adapter 實作 */
type Scanner struct{}

func init() { scanner.Register(&Scanner{}) }

func (s *Scanner) Name() string             { return binaryName }
func (s *Scanner) Category() model.Category { return model.CategorySCA }
func (s *Scanner) Binary() string           { return binaryName }
func (s *Scanner) VersionArgs() []string    { return []string{"--version"} }

/* TargetKinds osv-scanner 掃描本機路徑的依賴清單 lockfile SBOM 等 */
func (s *Scanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetPath}
}

/* InstallHint osv-scanner 安裝指引 支援 managed 自動安裝 */
func (s *Scanner) InstallHint() scanner.InstallHint {
	return scanner.InstallHint{
		DocsURL: "https://google.github.io/osv-scanner/installation/",
		Command: "vigila engine install osv-scanner",
	}
}

/* CheckInstalled 確認 osv-scanner 已安裝 */
func (s *Scanner) CheckInstalled() error {
	return scanner.CheckBinary(binaryName)
}

/*
	BuildCommand 組 osv-scanner 掃描指令

scan --format json 掃描目錄下所有可辨識的依賴清單 遞迴為預設
*/
func (s *Scanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	args := []string{"scan", "--format", "json", target}
	args = append(args, opts.ExtraArgs...)
	return binaryName, args
}

/* Run 執行掃描 stdout 即 JSON */
func (s *Scanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	binary, args := s.BuildCommand(target, opts)
	return scanner.RunEngine(ctx, s.Name(), target, binary, args)
}

/* ExitCodeIsFindings osv-scanner 發現漏洞時 exit 1 其餘非零為真正錯誤 */
func (s *Scanner) ExitCodeIsFindings(code int) bool {
	return code == 1
}

/* osvOutput 為 osv-scanner JSON 輸出結構 只取需要的欄位 */
type osvOutput struct {
	Results []osvResult `json:"results"`
}

type osvResult struct {
	Source   osvSource     `json:"source"`
	Packages []osvPackages `json:"packages"`
}

type osvSource struct {
	Path string `json:"path"`
}

type osvPackages struct {
	Package         osvPackage         `json:"package"`
	Vulnerabilities []osvVulnerability `json:"vulnerabilities"`
	Groups          []osvGroup         `json:"groups"`
}

type osvPackage struct {
	Name      string `json:"name"`
	Version   string `json:"version"`
	Ecosystem string `json:"ecosystem"`
}

type osvVulnerability struct {
	ID         string         `json:"id"`
	Aliases    []string       `json:"aliases"`
	Details    string         `json:"details"`
	References []osvReference `json:"references"`
}

type osvReference struct {
	URL string `json:"url"`
}

/*
	osvGroup 聚合相關漏洞 id max_severity 為該組最高 CVSS 分數字串

severity 不在各 vulnerability 而在 group 需以 ids 對映回各 vulnerability
*/
type osvGroup struct {
	IDs         []string `json:"ids"`
	MaxSeverity string   `json:"max_severity"`
}

/*
	Parse 將 osv-scanner JSON 轉為統一 Finding

每個 vulnerability 一筆 finding severity 由所屬 group 的 max_severity CVSS 分數換算
RuleID 優先取 CVE 別名 便於與 Grype Trivy 交叉比對 osv 原 id 保留於 UniqueIDFromTool
*/
func (s *Scanner) Parse(raw []byte) ([]model.Finding, error) {
	var out osvOutput
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("osv-scanner JSON 解析失敗: %w", err)
	}

	findings := make([]model.Finding, 0)
	for _, r := range out.Results {
		for _, p := range r.Packages {
			scoreByID := maxSeverityByID(p.Groups)
			for _, v := range p.Vulnerabilities {
				f := model.Finding{
					Engine:           binaryName,
					Category:         model.CategorySCA,
					RuleID:           preferCVE(v.ID, v.Aliases),
					Title:            preferCVE(v.ID, v.Aliases),
					Description:      v.Details,
					PkgName:          p.Package.Name,
					InstalledVersion: p.Package.Version,
					FilePath:         r.Source.Path,
					UniqueIDFromTool: v.ID + ":" + p.Package.Name,
				}

				if score, ok := scoreByID[v.ID]; ok && score > 0 {
					f.CVSSScore = &score
					f.Severity = core.SeverityFromCVSS(score)
				} else {
					f.Severity = model.SeverityUnknown
				}

				if urls := referenceURLs(v.References); len(urls) > 0 {
					f.References = urls
				}

				f.HashCode = core.Fingerprint(f)
				findings = append(findings, f)
			}
		}
	}
	return findings, nil
}

/* maxSeverityByID 建立 vulnerability id → 該組 max_severity CVSS 分數的對映 */
func maxSeverityByID(groups []osvGroup) map[string]float64 {
	byID := make(map[string]float64)
	for _, g := range groups {
		score, err := strconv.ParseFloat(g.MaxSeverity, 64)
		if err != nil {
			continue
		}
		for _, id := range g.IDs {
			byID[id] = score
		}
	}
	return byID
}

/* preferCVE 從別名取第一個 CVE 編號 供 RuleID 無則退回 osv 原 id */
func preferCVE(id string, aliases []string) string {
	for _, a := range aliases {
		if strings.HasPrefix(a, "CVE-") {
			return a
		}
	}
	return id
}

/* referenceURLs 抽出 reference 的 URL 略過空值 */
func referenceURLs(refs []osvReference) []string {
	urls := make([]string, 0, len(refs))
	for _, r := range refs {
		if r.URL != "" {
			urls = append(urls, r.URL)
		}
	}
	return urls
}
