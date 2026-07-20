package engine

import "fmt"

/*
	downloadSpec 描述一個引擎的官方 release 下載規則

命名差異封裝在 Asset 函式內 各引擎不同 版本一律由 GitHub latest 動態取得
只支援單一乾淨 binary 的引擎 semgrep（pip）與 nmap（無可攜 binary）不在此列
*/
type downloadSpec struct {
	Repo    string                                    // GitHub owner/repo
	BinName string                                    // 壓縮檔內 binary 名
	Asset   func(version, goos, goarch string) string // 依平台組 asset 名（含副檔名 格式由副檔名推導）
}

/* specs 為支援自動安裝的引擎下載規則表 */
var specs = map[string]downloadSpec{
	"gitleaks": {
		Repo:    "gitleaks/gitleaks",
		BinName: "gitleaks",
		/* gitleaks 用自訂 arch 詞 amd64→x64 386→x32 arm→armv7 且 windows 為 zip */
		Asset: func(version, goos, goarch string) string {
			ext := "tar.gz"
			if goos == "windows" {
				ext = "zip"
			}
			return fmt.Sprintf("gitleaks_%s_%s_%s.%s", version, goos, gitleaksArch(goarch), ext)
		},
	},
	"grype": {
		Repo:    "anchore/grype",
		BinName: "grype",
		Asset:   goreleaserAsset("grype"),
	},
	"syft": {
		Repo:    "anchore/syft",
		BinName: "syft",
		Asset:   goreleaserAsset("syft"),
	},
	"trufflehog": {
		Repo:    "trufflesecurity/trufflehog",
		BinName: "trufflehog",
		Asset:   goreleaserAsset("trufflehog"),
	},
	"nuclei": {
		Repo:    "projectdiscovery/nuclei",
		BinName: "nuclei",
		/* nuclei 為 zip 且 darwin 顯示為 macOS arch 仍用 goarch 原值 */
		Asset: func(version, goos, goarch string) string {
			os := goos
			if goos == "darwin" {
				os = "macOS"
			}
			return fmt.Sprintf("nuclei_%s_%s_%s.zip", version, os, goarch)
		},
	},
	"trivy": {
		Repo:    "aquasecurity/trivy",
		BinName: "trivy",
		/* trivy 命名最特殊 OS 首字母大寫 ARCH 改用 64bit ARM64 等自訂詞 */
		Asset: func(version, goos, goarch string) string {
			return fmt.Sprintf("trivy_%s_%s-%s.tar.gz", version, trivyOS(goos), trivyArch(goarch))
		},
	},
	"osv-scanner": {
		Repo:    "google/osv-scanner",
		BinName: "osv-scanner",
		/* osv-scanner 直接發佈裸 binary 非壓縮檔 檔名不含版本 windows 加 .exe */
		Asset: func(version, goos, goarch string) string {
			name := fmt.Sprintf("osv-scanner_%s_%s", goos, goarch)
			if goos == "windows" {
				name += ".exe"
			}
			return name
		},
	},
}

/*
	goreleaserAsset 回傳標準 goreleaser 命名的 asset 函式

慣例為 <name>_<version>_<goos>_<goarch>.tar.gz goos goarch 用 Go 原值小寫
grype syft trufflehog 於 linux darwin 皆採此命名
*/
func goreleaserAsset(name string) func(version, goos, goarch string) string {
	return func(version, goos, goarch string) string {
		return fmt.Sprintf("%s_%s_%s_%s.tar.gz", name, version, goos, goarch)
	}
}

/* gitleaksArch 把 GOARCH 對應到 gitleaks release 的 arch 詞 arm64 原樣 */
func gitleaksArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "x64"
	case "386":
		return "x32"
	case "arm":
		return "armv7"
	default:
		return goarch
	}
}

/* trivyOS 把 GOOS 對應到 trivy release 的 OS 詞 未知值回原值 */
func trivyOS(goos string) string {
	switch goos {
	case "linux":
		return "Linux"
	case "darwin":
		return "macOS"
	case "windows":
		return "Windows"
	case "freebsd":
		return "FreeBSD"
	default:
		return goos
	}
}

/* trivyArch 把 GOARCH 對應到 trivy release 的 ARCH 詞 未知值回原值 */
func trivyArch(goarch string) string {
	switch goarch {
	case "amd64":
		return "64bit"
	case "386":
		return "32bit"
	case "arm64":
		return "ARM64"
	case "arm":
		return "ARM"
	case "ppc64le":
		return "PPC64LE"
	case "s390x":
		return "s390x"
	default:
		return goarch
	}
}

/* specFor 取得引擎的下載規則 不支援自動安裝時回錯 */
func specFor(name string) (downloadSpec, error) {
	spec, ok := specs[name]
	if !ok {
		return downloadSpec{}, fmt.Errorf("引擎 %s 不支援自動安裝 請參考面板的安裝指引", name)
	}
	return spec, nil
}

/*
	IsInstallable 回報引擎是否可經 vigila 自動安裝（managed binary 下載）

供面板決定是否顯示一鍵安裝按鈕 semgrep（pip）checkov（pip）nmap（套件管理器）zap（套件）
不支援自動安裝 須由使用者依安裝指引手動處理
*/
func IsInstallable(name string) bool {
	_, ok := specs[name]
	return ok
}
