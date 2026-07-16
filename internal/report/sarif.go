// Package report 為報告匯出層
//
// 支援 SARIF 2.1.0 JSON HTML 三種格式
// SARIF 為 OASIS 標準 可上傳 GitHub code scanning
package report

import (
	"strconv"
	"strings"

	"github.com/cluion/vigila/internal/store/sqlc"
	"github.com/owenrumney/go-sarif/v2/sarif"
)

/* severityToSarifLevel 統一 severity 映射為 SARIF level

CRITICAL HIGH 對應 error
MEDIUM 對應 warning
LOW UNKNOWN 對應 note */
func severityToSarifLevel(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	default:
		return "note"
	}
}

/* severityToSecurityScore 把 severity 映射為 security-severity 分數

GitHub 約定大於 9 為 critical 7 到 8.9 為 high 4 到 6.9 為 medium 0.1 到 3.9 為 low */
func severityToSecurityScore(severity string) string {
	switch severity {
	case "CRITICAL":
		return "9.5"
	case "HIGH":
		return "7.5"
	case "MEDIUM":
		return "5.0"
	case "LOW":
		return "2.5"
	default:
		return "0.0"
	}
}

/* formatFloat 格式化 float64 為字串 */
func formatFloat(f float64) string {
	return strconv.FormatFloat(f, 'f', 1, 64)
}

/* GenerateSARIF 產生 SARIF 2.1.0 報告字串

每個引擎一個 run 同一個 SARIF 檔承載多引擎結果
result.properties 承載 CVSS CWE 修復版本等擴充資訊 */
func GenerateSARIF(scan sqlc.Scan, runs []sqlc.EngineRun, findings []sqlc.Finding) (string, error) {
	rpt, err := sarif.New(sarif.Version210)
	if err != nil {
		return "", err
	}

	byEngine := groupByEngine(findings)

	for _, run := range runs {
		engineFindings := byEngine[run.Engine]

		sarifRun := sarif.NewRunWithInformationURI(run.Engine, "https://vigila.dev")

		for _, f := range engineFindings {
			level := severityToSarifLevel(f.Severity)
			result := sarif.NewRuleResult(f.RuleID).
				WithLevel(level).
				WithMessage(sarif.NewTextMessage(f.Title))

			/* 位置資訊 */
			if f.FilePath != nil {
				physLoc := sarif.NewPhysicalLocation().
					WithArtifactLocation(sarif.NewArtifactLocation().WithUri(*f.FilePath))
				if f.StartLine != nil {
					region := sarif.NewRegion().WithStartLine(int(*f.StartLine))
					if f.EndLine != nil {
						region.WithEndLine(int(*f.EndLine))
					}
					physLoc.WithRegion(region)
				}
				loc := sarif.NewLocationWithPhysicalLocation(physLoc)
				result.WithLocations([]*sarif.Location{loc})
			}

			/* 擴充屬性 PropertyBag 內部 map 需先初始化 */
			pb := sarif.NewPropertyBag()
			pb.AddString("security-severity", severityToSecurityScore(f.Severity))
			pb.AddString("engine", f.Engine)
			pb.AddString("category", f.Category)
			if f.CvssScore != nil {
				pb.AddString("cvss_score", formatFloat(*f.CvssScore))
			}
			if f.Cwe != nil {
				pb.AddString("cwe", *f.Cwe)
			}
			if f.FixedVersion != nil {
				pb.AddString("fixed_version", *f.FixedVersion)
			}
			if f.PkgName != nil {
				pb.AddString("pkg_name", *f.PkgName)
			}
			result.AttachPropertyBag(pb)

			sarifRun.AddResult(result)
		}

		rpt.AddRun(sarifRun)
	}

	var buf strings.Builder
	if err := rpt.PrettyWrite(&buf); err != nil {
		return "", err
	}
	return buf.String(), nil
}

/* groupByEngine 依引擎分組 findings */
func groupByEngine(findings []sqlc.Finding) map[string][]sqlc.Finding {
	out := map[string][]sqlc.Finding{}
	for _, f := range findings {
		out[f.Engine] = append(out[f.Engine], f)
	}
	return out
}
