package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
)

/*
	managedDir 回傳 managed binary 存放目錄

優先讀 VIGILA_ENGINES_DIR 環境變數 供測試與進階使用者覆寫
否則預設 ~/.vigila/engines
*/
func managedDir() string {
	if d := os.Getenv("VIGILA_ENGINES_DIR"); d != "" {
		return d
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return ""
	}
	return filepath.Join(home, ".vigila", "engines")
}

/* ManagedDir 回傳 managed binary 存放目錄 供安裝流程寫入 */
func ManagedDir() string { return managedDir() }

/*
	managedPath 回傳 managed 目錄下該引擎的可執行檔路徑 找不到回空字串

Windows 補上 .exe 副檔名
*/
func managedPath(name string) string {
	dir := managedDir()
	if dir == "" {
		return ""
	}

	candidates := []string{name}
	if runtime.GOOS == "windows" {
		candidates = []string{name + ".exe", name}
	}
	for _, c := range candidates {
		p := filepath.Join(dir, c)
		if isExecutableFile(p) {
			return p
		}
	}
	return ""
}

/* isExecutableFile 判斷路徑是否為可執行的一般檔案 */
func isExecutableFile(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		return true // Windows 以副檔名判斷 由呼叫端保證
	}
	return info.Mode()&0o111 != 0
}

/*
	ResolveBinary 把引擎名稱解析成實際執行路徑

managed 優先 ~/.vigila/engines/ 有可執行檔就用它 釘選版不會被系統版蓋過
否則回原名 交由 PATH 解析
*/
func ResolveBinary(name string) string {
	if p := managedPath(name); p != "" {
		return p
	}
	return name
}

/*
CheckBinary 確認引擎可用 涵蓋 managed system docker 三來源

與 ResolveSource 一致 任一來源可用即通過 皆無才回錯 適用 Name 與 Binary 相同的引擎
*/
func CheckBinary(binary string) error {
	return CheckEngine(binary, binary)
}

/*
CheckEngine 以 engineName 與 binary 分別判定 供 Name 與 Binary 不同的引擎如 zap

docker 以 engineName 對應 profile managed 與 PATH 以 binary 判定 任一可用即通過
*/
func CheckEngine(engineName, binary string) error {
	if ResolveSourceFor(engineName, binary) != SourceMissing {
		return nil
	}
	return fmt.Errorf("找不到 %s 請先安裝 加入 PATH 或啟用 docker profile", binary)
}
