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

func TestSeverityFromCVSS(t *testing.T) {
	cases := []struct {
		score float64
		want  model.Severity
	}{
		{9.8, model.SeverityCritical},
		{9.0, model.SeverityCritical},
		{7.5, model.SeverityHigh},
		{7.0, model.SeverityHigh},
		{4.3, model.SeverityMedium},
		{4.0, model.SeverityMedium},
		{0.1, model.SeverityLow},
		{0.0, model.SeverityUnknown},
		{-1, model.SeverityUnknown},
	}
	for _, c := range cases {
		if got := SeverityFromCVSS(c.score); got != c.want {
			t.Errorf("SeverityFromCVSS(%.1f) = %v 預期 %v", c.score, got, c.want)
		}
	}
}
