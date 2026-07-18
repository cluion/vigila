package scanner

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDockerCapable(t *testing.T) {
	if !DockerCapable("semgrep") || !DockerCapable("zap") {
		t.Error("semgrep zap 應為 docker-capable")
	}
	if DockerCapable("gitleaks") || DockerCapable("nmap") {
		t.Error("gitleaks nmap 本輪不支援 docker")
	}
}

/* TestSetDockerProfile 勾選/取消引擎 docker 應正確增刪 .env 的 COMPOSE_PROFILES */
func TestSetDockerProfile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("COMPOSE_PROFILES", "") // 空環境變數 使讀取落到 .env

	/* 啟用 trivy 建立 .env */
	if err := SetDockerProfile("trivy", true); err != nil {
		t.Fatalf("啟用 trivy 失敗: %v", err)
	}
	if !DockerProfileEnabled("trivy") {
		t.Error("trivy 啟用後應已勾選")
	}

	/* 再啟用 grype 兩者並存 */
	if err := SetDockerProfile("grype", true); err != nil {
		t.Fatal(err)
	}
	if !DockerProfileEnabled("trivy") || !DockerProfileEnabled("grype") {
		t.Error("trivy grype 應同時勾選")
	}

	/* 重複啟用不出錯 冪等 */
	if err := SetDockerProfile("grype", true); err != nil {
		t.Errorf("重複啟用應冪等 實際 %v", err)
	}

	/* 停用 trivy 只剩 grype */
	if err := SetDockerProfile("trivy", false); err != nil {
		t.Fatal(err)
	}
	if DockerProfileEnabled("trivy") {
		t.Error("trivy 停用後應移除")
	}
	if !DockerProfileEnabled("grype") {
		t.Error("grype 應保留")
	}

	/* 非 docker-capable 引擎啟用應回錯 */
	if err := SetDockerProfile("gitleaks", true); err == nil {
		t.Error("gitleaks 不支援 docker 啟用應回錯")
	}
}

/* TestSetDockerProfilePreservesEnv 增刪 profile 不應破壞 .env 其他內容 */
func TestSetDockerProfilePreservesEnv(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("COMPOSE_PROFILES", "")

	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("# 我的設定\nDATABASE_URL=postgres://x\nCOMPOSE_PROFILES=semgrep\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := SetDockerProfile("trivy", true); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(envPath)
	if err != nil {
		t.Fatal(err)
	}
	content := string(data)
	for _, want := range []string{"# 我的設定", "DATABASE_URL=postgres://x", "semgrep", "trivy"} {
		if !contains(content, want) {
			t.Errorf(".env 應保留/含 %q 實際:\n%s", want, content)
		}
	}
}

/* contains 簡易子字串判斷 供測試 */
func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
