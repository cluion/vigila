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
