// Package sbom 產生與解析軟體物料清單 SBOM
//
// 以 syft 產 CycloneDX JSON 存為 scan artifact 與 finding 分開
// finding 是漏洞 SBOM 是套件清單 兩者資料形狀不同
package sbom

import (
	"encoding/json"
	"fmt"
)

/* Package 為 SBOM 中的一個套件項 供面板套件清單表顯示 */
type Package struct {
	Name     string   `json:"name"`
	Version  string   `json:"version"`
	Type     string   `json:"type"` // library os-package 等
	PURL     string   `json:"purl"`
	Licenses []string `json:"licenses"`
}

/* cdxLicense 對應 CycloneDX license 項 可能為 license.id license.name 或 expression */
type cdxLicense struct {
	License *struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	} `json:"license"`
	Expression string `json:"expression"`
}

/* cdxComponent 對應 CycloneDX component */
type cdxComponent struct {
	Type     string       `json:"type"`
	Name     string       `json:"name"`
	Version  string       `json:"version"`
	PURL     string       `json:"purl"`
	Licenses []cdxLicense `json:"licenses"`
}

/* cdxDoc 為 CycloneDX 文件頂層 只取需要的欄位 */
type cdxDoc struct {
	Components []cdxComponent `json:"components"`
}

/*
	ParsePackages 把 CycloneDX JSON 解析成套件清單

無 components 回空切片而非錯誤 授權支援 license.id license.name 與 expression 三種形式
*/
func ParsePackages(content []byte) ([]Package, error) {
	var doc cdxDoc
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("解析 CycloneDX 失敗: %w", err)
	}

	pkgs := make([]Package, 0, len(doc.Components))
	for _, c := range doc.Components {
		pkgs = append(pkgs, Package{
			Name:     c.Name,
			Version:  c.Version,
			Type:     c.Type,
			PURL:     c.PURL,
			Licenses: extractLicenses(c.Licenses),
		})
	}
	return pkgs, nil
}

/* extractLicenses 從 CycloneDX license 陣列取出授權字串 略過空值 */
func extractLicenses(licenses []cdxLicense) []string {
	out := []string{}
	for _, l := range licenses {
		switch {
		case l.License != nil && l.License.ID != "":
			out = append(out, l.License.ID)
		case l.License != nil && l.License.Name != "":
			out = append(out, l.License.Name)
		case l.Expression != "":
			out = append(out, l.Expression)
		}
	}
	return out
}
