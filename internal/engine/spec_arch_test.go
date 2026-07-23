package engine

import "testing"

func TestGitleaksArch(t *testing.T) {
	cases := map[string]string{"amd64": "x64", "386": "x32", "arm": "armv7", "arm64": "arm64", "riscv64": "riscv64"}
	for in, want := range cases {
		if got := gitleaksArch(in); got != want {
			t.Errorf("gitleaksArch(%q) = %q 預期 %q", in, got, want)
		}
	}
}

func TestTrivyOS(t *testing.T) {
	cases := map[string]string{
		"linux": "Linux", "darwin": "macOS", "windows": "Windows",
		"freebsd": "FreeBSD", "plan9": "plan9",
	}
	for in, want := range cases {
		if got := trivyOS(in); got != want {
			t.Errorf("trivyOS(%q) = %q 預期 %q", in, got, want)
		}
	}
}

func TestTrivyArch(t *testing.T) {
	cases := map[string]string{
		"amd64": "64bit", "386": "32bit", "arm64": "ARM64",
		"arm": "ARM", "ppc64le": "PPC64LE", "s390x": "s390x", "mips": "mips",
	}
	for in, want := range cases {
		if got := trivyArch(in); got != want {
			t.Errorf("trivyArch(%q) = %q 預期 %q", in, got, want)
		}
	}
}

func TestJoinWarning(t *testing.T) {
	if got := joinWarning("", "b"); got != "b" {
		t.Errorf("空 existing 應直接回 added 得 %q", got)
	}
	if got := joinWarning("a", "b"); got != "a；b" {
		t.Errorf("兩者串接不符 得 %q", got)
	}
}

func TestSpecForAndInstallable(t *testing.T) {
	if _, err := specFor("gitleaks"); err != nil {
		t.Errorf("gitleaks 應可自動安裝: %v", err)
	}
	if _, err := specFor("semgrep"); err == nil {
		t.Error("semgrep 不支援自動安裝應回錯")
	}
	if !IsInstallable("trivy") {
		t.Error("trivy 應為 installable")
	}
	if IsInstallable("nmap") {
		t.Error("nmap 不應為 installable")
	}
}
