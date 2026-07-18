package engine

import "testing"

func TestSpecForKnownEngine(t *testing.T) {
	spec, err := specFor("gitleaks")
	if err != nil {
		t.Fatalf("gitleaks 應有 download spec: %v", err)
	}
	if spec.Repo != "gitleaks/gitleaks" {
		t.Errorf("repo = %q 預期 gitleaks/gitleaks", spec.Repo)
	}

	got := spec.Asset("8.30.1", "darwin", "arm64")
	want := "gitleaks_8.30.1_darwin_arm64.tar.gz"
	if got != want {
		t.Errorf("asset 名 = %q 預期 %q", got, want)
	}
}

func TestSpecForUnsupportedEngine(t *testing.T) {
	/* semgrep 靠 pip nmap 無可攜 binary 皆不支援自動安裝 */
	for _, name := range []string{"semgrep", "nmap", "unknown-xyz"} {
		if _, err := specFor(name); err == nil {
			t.Errorf("%s 不應有 download spec", name)
		}
	}
}

/*
	TestSpecAssetNaming 驗證各引擎 asset 名依平台正確組出

命名慣例取自各引擎官方 release 實際檔名 gitleaks 用 x64 x32 armv7 且 windows 為 zip
grype trufflehog 走標準 goreleaser 命名 nuclei 為 zip 且 darwin 顯示為 macOS trivy 命名最特殊
格式由 asset 副檔名推導 與實際下載一致
*/
func TestSpecAssetNaming(t *testing.T) {
	cases := []struct {
		engine, version, goos, goarch string
		wantAsset, wantFormat         string
	}{
		/* gitleaks: amd64→x64 386→x32 arm→armv7 arm64 原樣 windows 為 zip */
		{"gitleaks", "8.30.1", "darwin", "arm64", "gitleaks_8.30.1_darwin_arm64.tar.gz", "tar.gz"},
		{"gitleaks", "8.30.1", "linux", "amd64", "gitleaks_8.30.1_linux_x64.tar.gz", "tar.gz"},
		{"gitleaks", "8.30.1", "darwin", "amd64", "gitleaks_8.30.1_darwin_x64.tar.gz", "tar.gz"},
		{"gitleaks", "8.30.1", "linux", "386", "gitleaks_8.30.1_linux_x32.tar.gz", "tar.gz"},
		{"gitleaks", "8.30.1", "windows", "amd64", "gitleaks_8.30.1_windows_x64.zip", "zip"},
		{"grype", "0.116.0", "darwin", "arm64", "grype_0.116.0_darwin_arm64.tar.gz", "tar.gz"},
		{"grype", "0.116.0", "linux", "amd64", "grype_0.116.0_linux_amd64.tar.gz", "tar.gz"},
		{"trufflehog", "3.95.9", "linux", "amd64", "trufflehog_3.95.9_linux_amd64.tar.gz", "tar.gz"},
		{"trufflehog", "3.95.9", "darwin", "arm64", "trufflehog_3.95.9_darwin_arm64.tar.gz", "tar.gz"},
		{"nuclei", "3.11.0", "linux", "amd64", "nuclei_3.11.0_linux_amd64.zip", "zip"},
		{"nuclei", "3.11.0", "darwin", "arm64", "nuclei_3.11.0_macOS_arm64.zip", "zip"},
		{"nuclei", "3.11.0", "windows", "amd64", "nuclei_3.11.0_windows_amd64.zip", "zip"},
		{"trivy", "0.72.0", "linux", "amd64", "trivy_0.72.0_Linux-64bit.tar.gz", "tar.gz"},
		{"trivy", "0.72.0", "darwin", "arm64", "trivy_0.72.0_macOS-ARM64.tar.gz", "tar.gz"},
		{"trivy", "0.72.0", "darwin", "amd64", "trivy_0.72.0_macOS-64bit.tar.gz", "tar.gz"},
		{"trivy", "0.72.0", "linux", "arm64", "trivy_0.72.0_Linux-ARM64.tar.gz", "tar.gz"},
		/* osv-scanner 直接發佈裸 binary 檔名不含版本 windows 加 .exe 格式為 raw */
		{"osv-scanner", "2.4.0", "linux", "amd64", "osv-scanner_linux_amd64", "raw"},
		{"osv-scanner", "2.4.0", "darwin", "arm64", "osv-scanner_darwin_arm64", "raw"},
		{"osv-scanner", "2.4.0", "windows", "amd64", "osv-scanner_windows_amd64.exe", "raw"},
	}

	for _, c := range cases {
		t.Run(c.engine+"_"+c.goos+"_"+c.goarch, func(t *testing.T) {
			spec, err := specFor(c.engine)
			if err != nil {
				t.Fatalf("%s 應支援自動安裝: %v", c.engine, err)
			}
			got := spec.Asset(c.version, c.goos, c.goarch)
			if got != c.wantAsset {
				t.Errorf("asset 名 = %q 預期 %q", got, c.wantAsset)
			}
			/* 格式由 asset 檔名推導 應與下載解壓一致 */
			if f := formatFromAsset(got); f != c.wantFormat {
				t.Errorf("format = %q 預期 %q", f, c.wantFormat)
			}
		})
	}
}
