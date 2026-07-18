package scanner

import (
	"fmt"
	"os"
	"slices"
	"strings"
)

/* envFileName 為 compose profile 勾選狀態所在的檔案 位於 vigila 執行目錄 */
const envFileName = ".env"

/* DockerCapable 回報引擎是否支援以 docker 執行 供面板決定是否顯示開關 */
func DockerCapable(engineName string) bool {
	return dockerCapable[engineName]
}

/* DockerProfileEnabled 回報引擎的 docker profile 是否已在 COMPOSE_PROFILES 勾選 */
func DockerProfileEnabled(engineName string) bool {
	return slices.Contains(composeProfiles(), engineName)
}

/*
	SetDockerProfile 勾選或取消引擎的 docker 執行 增刪 .env 的 COMPOSE_PROFILES

僅 docker-capable 引擎可勾選 冪等 已是目標狀態則不動檔案
保留 .env 其他設定與註解 只改寫 COMPOSE_PROFILES 一行
*/
func SetDockerProfile(engineName string, enabled bool) error {
	if !dockerCapable[engineName] {
		return fmt.Errorf("引擎 %s 不支援 docker 執行", engineName)
	}

	profiles := splitProfiles(envFileValue(envFileName, "COMPOSE_PROFILES"))
	has := slices.Contains(profiles, engineName)
	switch {
	case enabled && !has:
		profiles = append(profiles, engineName)
	case !enabled && has:
		profiles = slices.DeleteFunc(profiles, func(p string) bool { return p == engineName })
	default:
		return nil // 已是目標狀態 冪等
	}

	line := "COMPOSE_PROFILES=" + strings.Join(profiles, ",")
	return writeComposeProfilesLine(line)
}

/*
	writeComposeProfilesLine 改寫 .env 的 COMPOSE_PROFILES 整行 保留其他行與註解

固定寫入常數路徑 envFileName 找到未註解的 COMPOSE_PROFILES= 行即就地替換
找不到則附加於檔尾 檔案不存在則新建
*/
func writeComposeProfilesLine(fullLine string) error {
	var lines []string
	if data, err := os.ReadFile(envFileName); err == nil && len(data) > 0 {
		lines = strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	}

	const prefix = "COMPOSE_PROFILES="
	replaced := false
	for i, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, prefix) {
			lines[i] = fullLine
			replaced = true
			break
		}
	}
	if !replaced {
		lines = append(lines, fullLine)
	}

	out := strings.Join(lines, "\n") + "\n"
	/* envFileName 為固定常數 .env 非外部輸入 gosec 污點分析誤報 */
	if err := os.WriteFile(envFileName, []byte(out), 0o600); err != nil { // #nosec G703
		return fmt.Errorf("寫入 %s 失敗: %w", envFileName, err)
	}
	return nil
}
