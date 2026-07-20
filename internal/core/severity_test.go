package core

import (
	"testing"

	"github.com/cluion/vigila/internal/core/model"
)

/* TestNormalizeSeverity 各引擎 severity 字串應正確映射到統一 5 級 */
func TestNormalizeSeverity(t *testing.T) {
	cases := []struct {
		in   string
		want model.Severity
	}{
		{"CRITICAL", model.SeverityCritical},
		{"high", model.SeverityHigh},
		{" Medium ", model.SeverityMedium},
		{"LOW", model.SeverityLow},
		/* Grype 最低風險等級 應為 LOW 而非 UNKNOWN */
		{"Negligible", model.SeverityLow},
		{"NEGLIGIBLE", model.SeverityLow},
		/* Semgrep 舊格式 */
		{"ERROR", model.SeverityHigh},
		{"WARNING", model.SeverityMedium},
		{"INFO", model.SeverityLow},
		/* 未知字串落 UNKNOWN */
		{"", model.SeverityUnknown},
		{"bogus", model.SeverityUnknown},
	}
	for _, c := range cases {
		if got := NormalizeSeverity(c.in); got != c.want {
			t.Errorf("NormalizeSeverity(%q) = %v 預期 %v", c.in, got, c.want)
		}
	}
}
