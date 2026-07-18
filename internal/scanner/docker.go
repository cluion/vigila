package scanner

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

/*
	dockerCapable 為本輪支援以 docker 執行的引擎

只收 stdout 型路徑引擎 gitleaks 需寫檔 nuclei nmap 為 URL host 目標 掛載邏輯不同 皆延後
*/
var dockerCapable = map[string]bool{
	"semgrep":    true,
	"trivy":      true,
	"grype":      true,
	"trufflehog": true,
}

/*
	dockerEnabled 判定引擎是否可經 docker 執行

需 docker binary 存在 引擎支援 docker 且其 profile 已在 COMPOSE_PROFILES 勾選
*/
func dockerEnabled(engineName string) bool {
	if !dockerCapable[engineName] {
		return false
	}
	if _, err := exec.LookPath("docker"); err != nil {
		return false
	}
	return slices.Contains(composeProfiles(), engineName)
}

/*
	composeProfiles 取得已勾選的 compose profiles

優先讀 COMPOSE_PROFILES 環境變數 否則解析 cwd 的 .env 逗號分隔去空白
*/
func composeProfiles() []string {
	raw := os.Getenv("COMPOSE_PROFILES")
	if raw == "" {
		raw = envFileValue(".env", "COMPOSE_PROFILES")
	}
	return splitProfiles(raw)
}

/* splitProfiles 把逗號分隔字串切成去空白的非空項 */
func splitProfiles(raw string) []string {
	out := []string{}
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

/* envFileValue 從 .env 檔讀取指定 key 的值 找不到回空字串 */
func envFileValue(path, key string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()

	prefix := key + "="
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}
		if v, ok := strings.CutPrefix(line, prefix); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

/*
	dockerArgs 組出 docker compose run 的完整參數

同路徑掛載目標 -v absTarget:absTarget 讓容器內外路徑一致
args 中等於原 target 的那格換成絕對路徑 其餘原樣帶入
--profile 確保該引擎 service 被啟用 不依賴當下 COMPOSE_PROFILES
*/
func dockerArgs(engineName, target, absTarget string, args []string) []string {
	out := []string{
		"compose", "--profile", engineName, "run", "--rm",
		"-v", absTarget + ":" + absTarget, engineName,
	}
	for _, a := range args {
		if a == target {
			a = absTarget
		}
		out = append(out, a)
	}
	return out
}

/*
	dockerRun 以一次性容器執行引擎

目標解析為絕對路徑後同路徑掛載 交由 DefaultRun 執行 docker 指令並捕獲 stdout
*/
func dockerRun(ctx context.Context, engineName, target string, args []string) (*Result, error) {
	abs, err := filepath.Abs(target)
	if err != nil {
		abs = target
	}
	return DefaultRun(ctx, "docker", dockerArgs(engineName, target, abs, args))
}
