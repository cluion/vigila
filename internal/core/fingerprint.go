package core

import (
	"crypto/sha256"
	"fmt"
	"strings"

	"github.com/cluion/vigila/internal/core/model"
)

/*
	Fingerprint 依類別計算去重 hash

各類別公式

	SAST   engine + rule_id + file_path + start_line
	SCA    engine + cve + pkg_name + installed_version
	Secret engine + rule_id + file_path + start_line
	DAST   engine + rule_id + url
	VA     engine + rule_id + host + port
*/
func Fingerprint(f model.Finding) string {
	var parts []string
	parts = append(parts, f.Engine)

	switch f.Category {
	case model.CategorySAST, model.CategorySecret:
		parts = append(parts, f.RuleID, f.FilePath)
		if f.StartLine != nil {
			parts = append(parts, fmt.Sprintf("%d", *f.StartLine))
		}
	case model.CategorySCA:
		parts = append(parts, f.RuleID, f.PkgName, f.InstalledVersion)
	case model.CategoryDAST:
		parts = append(parts, f.RuleID, f.URL)
	case model.CategoryVA:
		parts = append(parts, f.RuleID, f.Host, f.Port)
	default:
		parts = append(parts, f.RuleID, f.FilePath)
	}

	raw := strings.Join(parts, "|")
	h := sha256.Sum256([]byte(raw))
	return fmt.Sprintf("%x", h[:16])
}
