package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestParseVersion(t *testing.T) {
	cases := []struct {
		name, output, want string
	}{
		{"gitleaks", "8.30.1\n", "8.30.1"},
		{"grype", "Application:         grype\nVersion:             0.116.0\nBuildDate:  2026-07-16\n", "0.116.0"},
		{"trivy", "Version: 0.72.0\nVulnerability DB:\n  Version: 2\n", "0.72.0"},
		{"trufflehog", "trufflehog 3.95.9\n", "3.95.9"},
		{"nuclei 帶 v 前綴與 ANSI", "\x1b[34mINF\x1b[0m Nuclei Engine Version: v3.11.0\n", "3.11.0"},
		{"semgrep", "1.168.0\n", "1.168.0"},
		{"nmap 兩段式", "Nmap version 7.95 ( https://nmap.org )\n", "7.95"},
		{"無版本", "some unrelated output\n", ""},
		{"空字串", "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseVersion(c.output); got != c.want {
				t.Errorf("parseVersion(%q) = %q 預期 %q", c.output, got, c.want)
			}
		})
	}
}

/* versionStub 為 DetectVersion 測試用假引擎 只需 Binary 與 VersionArgs */
type versionStub struct{ name string }

func (v *versionStub) Binary() string { return v.name }

/*
	TestDetectVersionRunsBinary 驗證 DetectVersion 真的執行 managed binary 並抽出版本

寫一個印版本的 shell script 到 managed 目錄 走完 resolve → exec → parse 全鏈
Windows 無 shell script 慣例 略過
*/
func TestDetectVersionRunsBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell script 假 binary 不適用 windows")
	}
	dir := t.TempDir()
	t.Setenv("VIGILA_ENGINES_DIR", dir)

	name := "verstub"
	script := "#!/bin/sh\necho 'stub version 4.5.6'\n"
	if err := os.WriteFile(filepath.Join(dir, name), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}

	if got := DetectVersion(&versionStub{name: name}); got != "4.5.6" {
		t.Errorf("DetectVersion = %q 預期 4.5.6", got)
	}

	/* 不存在的引擎 來源為 missing 不執行 回空字串 */
	if got := DetectVersion(&versionStub{name: "no-such-engine-xyz"}); got != "" {
		t.Errorf("未安裝引擎 DetectVersion 應回空字串 實際 %q", got)
	}
}

/* 補齊 Scanner 介面其餘方法 讓 versionStub 可作為 Scanner 傳入 */
func (v *versionStub) VersionArgs() []string { return []string{"version"} }
