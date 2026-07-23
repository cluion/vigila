package core

import (
	"testing"

	"github.com/cluion/vigila/internal/core/model"
)

func TestInt64Ptr(t *testing.T) {
	if int64Ptr(-1) != nil {
		t.Error("負值應回 nil")
	}
	if p := int64Ptr(5); p == nil || *p != 5 {
		t.Errorf("非負值應回指標 得 %v", p)
	}
}

func TestDeriveProjectName(t *testing.T) {
	cases := map[string]string{
		"https://example.com/path": "example.com",
		"scanme.nmap.org":          "scanme.nmap.org",
	}
	for in, want := range cases {
		if got := deriveProjectName(in); got != want {
			t.Errorf("deriveProjectName(%q) = %q 預期含 %q", in, got, want)
		}
	}
	/* 本機路徑取 basename */
	if got := deriveProjectName("/tmp/myapp"); got != "myapp" {
		t.Errorf("路徑應取 basename 實際 %q", got)
	}
}

func TestDeriveProjectKey(t *testing.T) {
	if got := deriveProjectKey("https://example.com/a/b"); got != "https://example.com" {
		t.Errorf("URL 應歸一到 scheme://host 實際 %q", got)
	}
	/* 同站台不同 path 應得同一 key */
	if deriveProjectKey("https://x.com/a") != deriveProjectKey("https://x.com/b") {
		t.Error("同站台不同 path 應歸一")
	}
}

func TestToUpsertParams(t *testing.T) {
	f := model.Finding{
		Engine:   "semgrep",
		Category: model.CategorySAST,
		RuleID:   "r1",
		Title:    "問題",
		Severity: model.SeverityHigh,
		HashCode: "h1",
	}
	p := toUpsertParams(f, "proj", "scan", "run")
	if p.ProjectID != "proj" || p.ScanID != "scan" || p.EngineRunID != "run" {
		t.Errorf("關聯欄位不符 %+v", p)
	}
	if p.Engine != "semgrep" || p.RuleID != "r1" || p.HashCode != "h1" {
		t.Errorf("核心欄位不符 %+v", p)
	}
	if p.ID == "" {
		t.Error("應產生 ULID")
	}
}
