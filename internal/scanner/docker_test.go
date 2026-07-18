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

	t.Run("不支援 docker 的引擎即使啟用 profile 也回 false", func(t *testing.T) {
		t.Setenv("COMPOSE_PROFILES", "gitleaks")
		if dockerEnabled("gitleaks") {
			t.Error("gitleaks 本輪不支援 docker 應回 false")
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
