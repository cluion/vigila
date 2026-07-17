package engine

import "fmt"

/*
	downloadSpec 描述一個引擎的官方 release 下載規則

命名差異封裝在 Asset 函式內 各引擎不同 版本一律由 GitHub latest 動態取得
只支援單一乾淨 binary 的引擎 semgrep（pip）與 nmap（無可攜 binary）不在此列
*/
type downloadSpec struct {
	Repo    string                                    // GitHub owner/repo
	Format  string                                    // tar.gz | zip
	BinName string                                    // 壓縮檔內 binary 名
	Asset   func(version, goos, goarch string) string // 依平台組 asset 名
}

/* specs 為支援自動安裝的引擎下載規則表 */
var specs = map[string]downloadSpec{
	"gitleaks": {
		Repo:    "gitleaks/gitleaks",
		Format:  "tar.gz",
		BinName: "gitleaks",
		Asset: func(version, goos, goarch string) string {
			return fmt.Sprintf("gitleaks_%s_%s_%s.tar.gz", version, goos, goarch)
		},
	},
}

/* specFor 取得引擎的下載規則 不支援自動安裝時回錯 */
func specFor(name string) (downloadSpec, error) {
	spec, ok := specs[name]
	if !ok {
		return downloadSpec{}, fmt.Errorf("引擎 %s 不支援自動安裝 請參考面板的安裝指引", name)
	}
	return spec, nil
}
