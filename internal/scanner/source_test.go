package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolveSource(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("VIGILA_ENGINES_DIR", dir)

	/* managed 目錄放一個可執行檔 應解析為 managed */
	name := "fake-engine"
	bin := name
	if runtime.GOOS == "windows" {
		bin = name + ".exe"
	}
	if err := os.WriteFile(filepath.Join(dir, bin), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got := ResolveSource(name); got != SourceManaged {
		t.Errorf("managed 引擎 source = %q 預期 %q", got, SourceManaged)
	}

	/* 三來源皆無的引擎 應為 missing */
	if got := ResolveSource("definitely-not-a-real-engine-xyz"); got != SourceMissing {
		t.Errorf("不存在引擎 source = %q 預期 %q", got, SourceMissing)
	}
}

/*
	TestResolveSourceDocker 本機沒裝但 docker profile 已勾選 來源應為 docker

以 PATH 只指向含假 docker 的目錄 確保引擎不在 system 也不在 managed 隔離出 docker 分支
*/
func TestResolveSourceDocker(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("假 docker script 不適用 windows")
	}
	pathDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(pathDir, "docker"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", pathDir)                   // semgrep 不在此 PATH 故非 system
	t.Setenv("VIGILA_ENGINES_DIR", t.TempDir()) // 空 managed 目錄 故非 managed
	t.Setenv("COMPOSE_PROFILES", "semgrep")

	if got := ResolveSource("semgrep"); got != SourceDocker {
		t.Errorf("本機無 semgrep 但 profile 已勾選 source = %q 預期 %q", got, SourceDocker)
	}
}

/*
	TestResolveSourceDockerBeatsPath 明確勾選 docker 應蓋過偶然在 PATH 的系統版

使用者在 UI 勾了 docker 即使機器上剛好有同名 binary 也應以 docker 為準 符合明確選擇優先
*/
func TestResolveSourceDockerBeatsPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("假 script 不適用 windows")
	}
	pathDir := t.TempDir()
	/* PATH 同時放假 docker 與假 semgrep 使 semgrep 也在 system 可見 */
	for _, name := range []string{"docker", "semgrep"} {
		if err := os.WriteFile(filepath.Join(pathDir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", pathDir)
	t.Setenv("VIGILA_ENGINES_DIR", t.TempDir()) // 空 managed
	t.Setenv("COMPOSE_PROFILES", "semgrep")

	if got := ResolveSource("semgrep"); got != SourceDocker {
		t.Errorf("已勾選 docker 應蓋過 PATH source = %q 預期 %q", got, SourceDocker)
	}

	/* 未勾選 profile 時 落回 system */
	t.Setenv("COMPOSE_PROFILES", "")
	if got := ResolveSource("semgrep"); got != SourceSystem {
		t.Errorf("未勾選 docker 應用 system source = %q 預期 %q", got, SourceSystem)
	}
}
