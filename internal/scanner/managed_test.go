package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

/* writeExecutable 在 dir 下建一個可執行的假 binary */
func writeExecutable(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatalf("建立假 binary 失敗: %v", err)
	}
	return path
}

func TestResolveBinaryManagedFirst(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("此測試針對 Unix 執行位")
	}
	dir := t.TempDir()
	t.Setenv("VIGILA_ENGINES_DIR", dir)

	t.Run("managed 目錄有可執行檔時回完整路徑", func(t *testing.T) {
		want := writeExecutable(t, dir, "faketool")
		if got := ResolveBinary("faketool"); got != want {
			t.Errorf("ResolveBinary = %q 預期 managed 路徑 %q", got, want)
		}
	})

	t.Run("managed 沒有時回原名 交由 PATH 解析", func(t *testing.T) {
		if got := ResolveBinary("nonexistent-xyz"); got != "nonexistent-xyz" {
			t.Errorf("ResolveBinary = %q 預期原名", got)
		}
	})

	t.Run("managed 優先於 PATH", func(t *testing.T) {
		/* sh 一定在 PATH 上 在 managed 放同名 應回 managed 路徑而非 /bin/sh */
		want := writeExecutable(t, dir, "sh")
		if got := ResolveBinary("sh"); got != want {
			t.Errorf("ResolveBinary(sh) = %q 預期 managed 路徑 %q（managed 應優先於 PATH）", got, want)
		}
	})

	t.Run("managed 有檔但不可執行時不算 回原名", func(t *testing.T) {
		path := filepath.Join(dir, "notexec")
		if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
			t.Fatalf("建立檔案失敗: %v", err)
		}
		if got := ResolveBinary("notexec"); got != "notexec" {
			t.Errorf("ResolveBinary = %q 不可執行的檔案不應命中 managed", got)
		}
	})
}

func TestCheckBinaryManaged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("此測試針對 Unix 執行位")
	}
	dir := t.TempDir()
	t.Setenv("VIGILA_ENGINES_DIR", dir)

	t.Run("managed 有可執行檔視為已安裝", func(t *testing.T) {
		writeExecutable(t, dir, "managed-only")
		if err := CheckBinary("managed-only"); err != nil {
			t.Errorf("managed 有 binary 應視為已安裝 得到錯誤: %v", err)
		}
	})

	t.Run("managed 與 PATH 都沒有時回錯", func(t *testing.T) {
		if err := CheckBinary("definitely-not-here-xyz"); err == nil {
			t.Error("managed 與 PATH 都沒有應回錯")
		}
	})
}
