package sbom

import (
	"sort"
	"strings"
)

/*
	PackageChange 為同一套件的版本變動

coordinate 相同但版本不同 供供應鏈漂移報告顯示 old → new
*/
type PackageChange struct {
	Name       string `json:"name"`
	Type       string `json:"type"`
	PURL       string `json:"purl"`
	OldVersion string `json:"old_version"`
	NewVersion string `json:"new_version"`
}

/*
	Diff 為兩份 SBOM 的差異

Added 為 to 有 from 無 Removed 反之 Changed 為同套件版本變動 Unchanged 為完全相同的套件數
所有切片恆非 nil 供 JSON 序列化為 [] 而非 null
*/
type Diff struct {
	Added     []Package       `json:"added"`
	Removed   []Package       `json:"removed"`
	Changed   []PackageChange `json:"changed"`
	Unchanged int             `json:"unchanged"`
}

/*
	coordinateKey 回傳套件識別鍵 忽略版本

優先以 purl 去除版本作為 coordinate 如 pkg:npm/lodash@4.17.21 → pkg:npm/lodash
版本分隔的 @ 位於名稱之後 故取最後一個 / 之後的 @ 才是版本 避免誤切
npm scoped 套件 pkg:npm/@babel/core@7.0.0 的 @babel 不是版本 → pkg:npm/@babel/core
無 purl 時退回 type|name 使同名不同生態的套件 os-package 與 library 不相混
*/
func coordinateKey(p Package) string {
	if p.PURL == "" {
		return p.Type + "|" + p.Name
	}

	purl := p.PURL
	/* 先去除 qualifiers 與 subpath 其內可能含 @ 干擾版本判斷 */
	if i := strings.IndexAny(purl, "?#"); i >= 0 {
		purl = purl[:i]
	}
	/* 版本 @ 必在最後一段 / 之後 scope 的 @ 在其前 不可誤切 */
	if at := strings.LastIndexByte(purl, '@'); at > strings.LastIndexByte(purl, '/') {
		return purl[:at]
	}
	return purl
}

/*
	DiffPackages 比較兩份套件清單 以 coordinate 識別 from 為舊 to 為新

同一份清單內 coordinate 重複時後者覆蓋 罕見情境下版本比較取最後出現者
*/
func DiffPackages(from, to []Package) Diff {
	fromByKey := indexByCoordinate(from)
	toByKey := indexByCoordinate(to)

	diff := Diff{
		Added:   []Package{},
		Removed: []Package{},
		Changed: []PackageChange{},
	}

	for key, np := range toByKey {
		op, ok := fromByKey[key]
		if !ok {
			diff.Added = append(diff.Added, np)
			continue
		}
		if op.Version == np.Version {
			diff.Unchanged++
			continue
		}
		diff.Changed = append(diff.Changed, PackageChange{
			Name:       np.Name,
			Type:       np.Type,
			PURL:       np.PURL,
			OldVersion: op.Version,
			NewVersion: np.Version,
		})
	}

	for key, op := range fromByKey {
		if _, ok := toByKey[key]; !ok {
			diff.Removed = append(diff.Removed, op)
		}
	}

	sortPackages(diff.Added)
	sortPackages(diff.Removed)
	sort.Slice(diff.Changed, func(i, j int) bool { return diff.Changed[i].Name < diff.Changed[j].Name })
	return diff
}

/* indexByCoordinate 建立 coordinate → Package 索引 後出現者覆蓋 */
func indexByCoordinate(pkgs []Package) map[string]Package {
	idx := make(map[string]Package, len(pkgs))
	for _, p := range pkgs {
		idx[coordinateKey(p)] = p
	}
	return idx
}

/* sortPackages 依名稱再版本原地排序 使輸出穩定 */
func sortPackages(pkgs []Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})
}
