package report

import (
	"encoding/json"

	"github.com/cluion/vigila/internal/store/sqlc"
)

/* ReportData 為報告的結構化資料 JSON 匯出用 */
type ReportData struct {
	Scan       sqlc.Scan        `json:"scan"`
	EngineRuns []sqlc.EngineRun `json:"engine_runs"`
	Findings   []sqlc.Finding   `json:"findings"`
	Summary    Summary          `json:"summary"`
}

/* Summary 為嚴重度統計摘要 */
type Summary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Unknown  int `json:"unknown"`
}

/* BuildReportData 組裝報告資料 供 JSON 與 HTML 共用 */
func BuildReportData(scan sqlc.Scan, runs []sqlc.EngineRun, findings []sqlc.Finding) ReportData {
	s := Summary{}
	for _, f := range findings {
		s.Total++
		switch f.Severity {
		case "CRITICAL":
			s.Critical++
		case "HIGH":
			s.High++
		case "MEDIUM":
			s.Medium++
		case "LOW":
			s.Low++
		default:
			s.Unknown++
		}
	}
	return ReportData{
		Scan:       scan,
		EngineRuns: runs,
		Findings:   findings,
		Summary:    s,
	}
}

/* GenerateJSON 產生 JSON 格式報告 */
func GenerateJSON(scan sqlc.Scan, runs []sqlc.EngineRun, findings []sqlc.Finding) (string, error) {
	data := BuildReportData(scan, runs, findings)
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return "", err
	}
	return string(b), nil
}
