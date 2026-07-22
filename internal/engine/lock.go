package engine

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/cluion/vigila/internal/scanner"
)

/* lockFileName 為 managed 目錄下的版本記錄檔 記錄各引擎安裝版本與釘選狀態 */
const lockFileName = "engines.lock.json"

/* lockEntry 為一個引擎的安裝記錄 Pinned 表示 install <name>@<version> 明確釘選 */
type lockEntry struct {
	Version           string `json:"version"`
	Pinned            bool   `json:"pinned"`
	SHA256            string `json:"sha256"`
	SignatureVerified bool   `json:"signature_verified"`
}

/*
	parseInstallArg 解析 install 引數 <name>[@<version>]

version 可帶 v 前綴（自動去除）@latest 表示明確抓最新並解除釘選
無 @ 時 version 為空字串 由安裝流程決定沿用釘選或抓 latest
*/
func parseInstallArg(arg string) (string, string, error) {
	name, version, found := strings.Cut(arg, "@")
	if name == "" {
		return "", "", fmt.Errorf("安裝引數 %q 缺引擎名 格式為 <name>[@<version>]", arg)
	}
	if found && version == "" {
		return "", "", fmt.Errorf("安裝引數 %q 缺版本號 格式為 <name>[@<version>]", arg)
	}
	if version != "latest" {
		version = strings.TrimPrefix(version, "v")
	}
	return name, version, nil
}

/*
	readLock 讀取 managed 目錄的版本記錄

lock 為輔助記錄 檔案不存在或損毀時視為無記錄回空表 不阻擋安裝
*/
func readLock(dir string) map[string]lockEntry {
	data, err := os.ReadFile(filepath.Join(dir, lockFileName)) // #nosec G304 -- dir 為 managed 目錄非使用者輸入
	if err != nil {
		return map[string]lockEntry{}
	}
	var lock map[string]lockEntry
	if err := json.Unmarshal(data, &lock); err != nil || lock == nil {
		return map[string]lockEntry{}
	}
	return lock
}

/* writeLockEntry 更新單一引擎的記錄 讀改寫保留其他引擎項目 */
func writeLockEntry(dir, name string, entry lockEntry) error {
	lock := readLock(dir)
	lock[name] = entry

	data, err := json.MarshalIndent(lock, "", "  ")
	if err != nil {
		return fmt.Errorf("序列化版本記錄失敗: %w", err)
	}
	if err := os.WriteFile(filepath.Join(dir, lockFileName), data, 0o600); err != nil {
		return fmt.Errorf("寫入版本記錄失敗: %w", err)
	}
	return nil
}

/*
	PinnedVersions 回傳已釘選引擎的版本表 供面板與 API 呈現釘選狀態

讀 managed 目錄的版本記錄 只含 Pinned 為 true 的引擎
*/
func PinnedVersions() map[string]string {
	pins := map[string]string{}
	for name, entry := range readLock(scanner.ManagedDir()) {
		if entry.Pinned {
			pins[name] = entry.Version
		}
	}
	return pins
}
