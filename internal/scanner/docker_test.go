package scanner

import (
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestComposeProfiles(t *testing.T) {
	t.Run("讀環境變數 COMPOSE_PROFILES", func(t *testing.T) {
		t.Setenv("COMPOSE_PROFILES", "semgrep, trivy ,grype")
		got := composeProfiles()
		want := []string{"semgrep", "trivy", "grype"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("composeProfiles = %v 預期 %v", got, want)
		}
	})

	t.Run("環境變數為空時解析 cwd 的 .env", func(t *testing.T) {
		t.Setenv("COMPOSE_PROFILES", "")
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("# 註解\nCOMPOSE_PROFILES=semgrep,trufflehog\nOTHER=x\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		t.Chdir(dir)
		got := composeProfiles()
		want := []string{"semgrep", "trufflehog"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("composeProfiles = %v 預期 %v", got, want)
		}
	})

	t.Run("皆無時回空", func(t *testing.T) {
		t.Setenv("COMPOSE_PROFILES", "")
		t.Chdir(t.TempDir())
		if got := composeProfiles(); len(got) != 0 {
			t.Errorf("composeProfiles = %v 預期空", got)
		}
	})
}

func TestDockerEnabled(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("假 docker script 不適用 windows")
	}
	/* 造一個假的 docker 可執行檔並讓 PATH 只指向它 */
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	t.Run("docker 存在且引擎 profile 啟用 可支援 docker 的引擎回 true", func(t *testing.T) {
		t.Setenv("COMPOSE_PROFILES", "semgrep")
		if !dockerEnabled("semgrep") {
			t.Error("semgrep 已啟用 profile 應回 true")
		}
	})

	t.Run("profile 未啟用回 false", func(t *testing.T) {
		t.Setenv("COMPOSE_PROFILES", "trivy")
		if dockerEnabled("semgrep") {
			t.Error("semgrep 未在 profile 應回 false")
		}
	})

	t.Run("nmap 需 host 網路 尚未接入 docker", func(t *testing.T) {
		t.Setenv("COMPOSE_PROFILES", "nmap")
		if dockerEnabled("nmap") {
			t.Error("nmap 尚未支援 docker 應回 false")
		}
	})

	t.Run("osv-scanner checkov zap nuclei gitleaks 皆支援 docker", func(t *testing.T) {
		for _, e := range []string{"osv-scanner", "checkov", "zap", "nuclei", "gitleaks"} {
			t.Setenv("COMPOSE_PROFILES", e)
			if !dockerEnabled(e) {
				t.Errorf("%s 已啟用 profile 應支援 docker", e)
			}
		}
	})
}

func TestDockerEnabledNoDocker(t *testing.T) {
	/* PATH 指向空目錄 找不到 docker */
	t.Setenv("PATH", t.TempDir())
	t.Setenv("COMPOSE_PROFILES", "semgrep")
	if dockerEnabled("semgrep") {
		t.Error("找不到 docker 應回 false")
	}
}

func TestDockerArgs(t *testing.T) {
	args := []string{"scan", "--config", "p/default", "--json", "./myapp"}
	got := dockerArgs("semgrep", "./myapp", "/home/u/myapp", args)
	want := []string{
		"compose", "--profile", "semgrep", "run", "--rm",
		"-v", "/home/u/myapp:/home/u/myapp", "semgrep",
		"scan", "--config", "p/default", "--json", "/home/u/myapp",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dockerArgs =\n%v\n預期\n%v", got, want)
	}
}

/*
	TestDockerArgsPrefixedTarget grype 以 dir:target 形式帶目標 須連前綴一起重映射

否則容器收到未掛載的相對路徑 掃到空目錄
*/
func TestDockerArgsPrefixedTarget(t *testing.T) {
	args := []string{"dir:./app", "-o", "json"}
	got := dockerArgs("grype", "./app", "/abs/app", args)
	want := []string{
		"compose", "--profile", "grype", "run", "--rm",
		"-v", "/abs/app:/abs/app", "grype",
		"dir:/abs/app", "-o", "json",
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("dockerArgs =\n%v\n預期\n%v", got, want)
	}
}

func TestRemapTarget(t *testing.T) {
	cases := []struct{ arg, target, abs, want string }{
		{"./app", "./app", "/abs/app", "/abs/app"},                   // trivy 裸路徑
		{"dir:./app", "./app", "/abs/app", "dir:/abs/app"},           // grype dir: 前綴
		{"--config=./app", "./app", "/abs/app", "--config=/abs/app"}, // = 前綴
		{"p/default", "./app", "/abs/app", "p/default"},              // 不含目標 原樣
		{"./application", "./app", "/abs/app", "./application"},      // 非邊界子字串 不誤傷
	}
	for _, c := range cases {
		if got := remapTarget(c.arg, c.target, c.abs); got != c.want {
			t.Errorf("remapTarget(%q,%q) = %q 預期 %q", c.arg, c.target, got, c.want)
		}
	}
}
