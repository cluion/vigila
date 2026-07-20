package core

import (
	"testing"

	"github.com/cluion/vigila/internal/core/model"
)

/*
	TestDASTFingerprintDistinguishesMethod 同一 rule 與 URL 但不同 HTTP method
	應產生不同 fingerprint 否則 GET 與 POST 的發現會被誤去重成一筆
*/
func TestDASTFingerprintDistinguishesMethod(t *testing.T) {
	base := model.Finding{
		Engine:   "nuclei",
		Category: model.CategoryDAST,
		RuleID:   "xss",
		URL:      "http://example.com/search",
	}
	get := base
	get.Method = "GET"
	post := base
	post.Method = "POST"

	if Fingerprint(get) == Fingerprint(post) {
		t.Error("同 URL 不同 method 的 DAST 發現 fingerprint 不應相同")
	}
}

/* TestFingerprintStableForSameInput 相同輸入應得穩定一致的 fingerprint */
func TestFingerprintStableForSameInput(t *testing.T) {
	var line int64 = 42
	f := model.Finding{
		Engine:    "semgrep",
		Category:  model.CategorySAST,
		RuleID:    "sql-injection",
		FilePath:  "app/db.go",
		StartLine: &line,
	}
	if Fingerprint(f) != Fingerprint(f) {
		t.Error("相同輸入的 fingerprint 應一致")
	}
}
