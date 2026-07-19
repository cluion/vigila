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
	dockerCapable 為支援以 docker 執行的引擎

只收 stdout 型路徑引擎 掛載目標路徑 捕獲 stdout 即可
gitleaks 需寫檔 nuclei zap 為 URL 目標且 zap 寫檔 nmap 為 host 目標需 network 皆另行處理
*/
var dockerCapable = map[string]bool{
	"semgrep":     true,
	"trivy":       true,
	"grype":       true,
	"trufflehog":  true,
	"osv-scanner": true,
	"checkov":     true,
	"zap":         true,
	"nuclei":      true,
	"gitleaks":    true,
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
		out = append(out, remapTarget(a, target, absTarget))
	}
	return out
}

/*
	remapTarget 把引數中的目標路徑換成掛載用的絕對路徑

處理兩種形式 引數本身即 target（trivy）或帶分隔前綴 如 grype 的 dir:target
只在整段相等或以 sep+target 結尾時替換 避免誤傷含相同子字串的其他引數
*/
func remapTarget(arg, target, absTarget string) string {
	if arg == target {
		return absTarget
	}
	for _, sep := range []string{":", "="} {
		if suffix := sep + target; strings.HasSuffix(arg, suffix) {
			return arg[:len(arg)-len(target)] + absTarget
		}
	}
	return arg
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

/*
	DockerRunNoMount 對 URL host 目標的引擎以容器執行 不掛載任何目錄

目標透過 args 直接傳入 如 nuclei -u <url> 捕獲 stdout 供 URL host 型引擎的 Run 呼叫
--profile 確保該引擎 service 被啟用 不依賴當下 COMPOSE_PROFILES
*/
func DockerRunNoMount(ctx context.Context, engineName string, args []string) (*Result, error) {
	full := append([]string{"compose", "--profile", engineName, "run", "--rm", engineName}, args...)
	return DefaultRun(ctx, "docker", full)
}

/*
	DockerReportArgs 組出「掛目標 + 掛輸出目錄」的 compose run 參數 供寫檔型路徑引擎

如 gitleaks 掃 absTarget 但報告寫入 outDir 兩者皆同路徑掛載 讓容器內外一致
user 非空時以 --user 指定容器身分 讓報告可寫入 0o700 目錄 保護含密鑰的報告不外洩
呼叫端負責在 args 內以 outDir 下的路徑指定報告輸出 並於執行後讀回
*/
func DockerReportArgs(engineName, absTarget, outDir, user string, args []string) []string {
	/* bind mount 預設可寫 不加 :rw 同路徑掛載加 :rw 在部分 runtime 會失效 */
	out := []string{"compose", "--profile", engineName, "run", "--rm"}
	if user != "" {
		out = append(out, "--user", user)
	}
	out = append(out,
		"-v", absTarget+":"+absTarget,
		"-v", outDir+":"+outDir,
		engineName,
	)
	return append(out, args...)
}
