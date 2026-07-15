package core

import (
	"strings"

	"github.com/cluion/vigila/internal/core/model"
)

/* NormalizeSeverity 將各引擎的 severity 字串統一為 5 級

Semgrep INFO WARNING ERROR 及新版 HIGH MEDIUM LOW CRITICAL
Trivy 已對齊 UNKNOWN LOW MEDIUM HIGH CRITICAL
Gitleaks 無 severity 由 adapter 自行映射 */
func NormalizeSeverity(s string) model.Severity {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	case "ERROR":
		return model.SeverityHigh
	case "WARNING":
		return model.SeverityMedium
	case "INFO":
		return model.SeverityLow
	default:
		return model.SeverityUnknown
	}
}
