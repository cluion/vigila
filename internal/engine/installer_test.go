package engine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

/* buildGitleaksTarGz 造一個含 gitleaks binary 的 tar.gz 回傳位元組與其 sha256 */
func buildGitleaksTarGz(t *testing.T, content string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{"LICENSE": "mit", "gitleaks": content} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()

	sum := sha256.Sum256(buf.Bytes())
	return buf.Bytes(), hex.EncodeToString(sum[:])
}

/* fakeGH 回傳一組模擬 GitHub 回應的 Get 函式與各 URL */
func fakeGH(t *testing.T, tarGz []byte, sha string, corrupt bool) func(string) ([]byte, int, error) {
	t.Helper()
	const assetURL = "https://example.com/gitleaks_8.30.1_darwin_arm64.tar.gz"
	const checksumsURL = "https://example.com/gitleaks_8.30.1_checksums.txt"

	release := map[string]any{
		"tag_name": "v8.30.1",
		"assets": []map[string]string{
			{"name": "gitleaks_8.30.1_darwin_arm64.tar.gz", "browser_download_url": assetURL},
			{"name": "gitleaks_8.30.1_checksums.txt", "browser_download_url": checksumsURL},
		},
	}
	releaseJSON, _ := json.Marshal(release)
	checksums := []byte(sha + "  gitleaks_8.30.1_darwin_arm64.tar.gz\n")

	body := tarGz
	if corrupt {
		body = append([]byte("tampered"), tarGz...)
	}

	return func(url string) ([]byte, int, error) {
		switch url {
		case "https://api.github.com/repos/gitleaks/gitleaks/releases/latest",
			"https://api.github.com/repos/gitleaks/gitleaks/releases/tags/v8.30.1":
			return releaseJSON, 200, nil
		case assetURL:
			return body, 200, nil
		case checksumsURL:
			return checksums, 200, nil
		}
		return nil, 404, nil
	}
}

/* recordGet 包裝 Get 函式 記錄請求過的 URL 供斷言走了 latest 或 tag 端點 */
func recordGet(get func(string) ([]byte, int, error), urls *[]string) func(string) ([]byte, int, error) {
	return func(url string) ([]byte, int, error) {
		*urls = append(*urls, url)
		return get(url)
	}
}

/* contains 回報字串切片是否含指定元素 */
func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func TestInstallWritesManagedBinary(t *testing.T) {
	tarGz, sha := buildGitleaksTarGz(t, "REAL-GITLEAKS")
	dir := t.TempDir()

	in := &Installer{DestDir: dir, GOOS: "darwin", GOARCH: "arm64", Get: fakeGH(t, tarGz, sha, false)}
	res, err := in.Install("gitleaks")
	if err != nil {
		t.Fatalf("install 失敗: %v", err)
	}

	if res.Version != "8.30.1" {
		t.Errorf("版本 = %q 預期 8.30.1", res.Version)
	}

	path := filepath.Join(dir, "gitleaks")
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取安裝後的 binary 失敗: %v", err)
	}
	if string(got) != "REAL-GITLEAKS" {
		t.Errorf("binary 內容 = %q 預期 REAL-GITLEAKS", got)
	}

	info, _ := os.Stat(path)
	if info.Mode()&0o111 == 0 {
		t.Error("安裝後的 binary 應有執行權限")
	}
}

func TestInstallRejectsChecksumMismatch(t *testing.T) {
	tarGz, sha := buildGitleaksTarGz(t, "REAL-GITLEAKS")
	dir := t.TempDir()

	/* corrupt 讓下載內容與 checksums 記錄的 sha 不符 */
	in := &Installer{DestDir: dir, GOOS: "darwin", GOARCH: "arm64", Get: fakeGH(t, tarGz, sha, true)}
	_, err := in.Install("gitleaks")
	if err == nil {
		t.Fatal("checksum 不符應中止安裝")
	}

	if _, statErr := os.Stat(filepath.Join(dir, "gitleaks")); !os.IsNotExist(statErr) {
		t.Error("checksum 不符時不應寫入 binary")
	}
}

const (
	latestURL = "https://api.github.com/repos/gitleaks/gitleaks/releases/latest"
	tagURL    = "https://api.github.com/repos/gitleaks/gitleaks/releases/tags/v8.30.1"
)

func TestInstallPinnedVersion(t *testing.T) {
	tarGz, sha := buildGitleaksTarGz(t, "REAL-GITLEAKS")
	dir := t.TempDir()

	var urls []string
	in := &Installer{DestDir: dir, GOOS: "darwin", GOARCH: "arm64",
		Get: recordGet(fakeGH(t, tarGz, sha, false), &urls)}
	res, err := in.Install("gitleaks@8.30.1")
	if err != nil {
		t.Fatalf("釘選安裝失敗: %v", err)
	}

	if !contains(urls, tagURL) || contains(urls, latestURL) {
		t.Errorf("釘選安裝應走 tag 端點而非 latest 實際請求 %v", urls)
	}
	if !res.Pinned || res.Version != "8.30.1" {
		t.Errorf("結果應為釘選 8.30.1 得 pinned=%v version=%q", res.Pinned, res.Version)
	}

	entry := readLock(dir)["gitleaks"]
	if !entry.Pinned || entry.Version != "8.30.1" {
		t.Errorf("lock 應記錄釘選 8.30.1 得 %+v", entry)
	}
	if entry.SHA256 != sha {
		t.Errorf("lock sha256 = %q 預期 %q", entry.SHA256, sha)
	}
}

func TestInstallReusesPin(t *testing.T) {
	tarGz, sha := buildGitleaksTarGz(t, "REAL-GITLEAKS")
	dir := t.TempDir()

	/* 先前已釘選 8.30.1 純 install 應沿用釘選版本而非抓 latest */
	if err := writeLockEntry(dir, "gitleaks", lockEntry{Version: "8.30.1", Pinned: true}); err != nil {
		t.Fatal(err)
	}

	var urls []string
	in := &Installer{DestDir: dir, GOOS: "darwin", GOARCH: "arm64",
		Get: recordGet(fakeGH(t, tarGz, sha, false), &urls)}
	res, err := in.Install("gitleaks")
	if err != nil {
		t.Fatalf("沿用釘選安裝失敗: %v", err)
	}

	if !contains(urls, tagURL) || contains(urls, latestURL) {
		t.Errorf("有釘選時純 install 應走 tag 端點 實際請求 %v", urls)
	}
	if !res.Pinned {
		t.Error("沿用釘選後結果應維持 pinned")
	}
}

func TestInstallLatestUnpins(t *testing.T) {
	tarGz, sha := buildGitleaksTarGz(t, "REAL-GITLEAKS")
	dir := t.TempDir()

	if err := writeLockEntry(dir, "gitleaks", lockEntry{Version: "8.0.0", Pinned: true}); err != nil {
		t.Fatal(err)
	}

	var urls []string
	in := &Installer{DestDir: dir, GOOS: "darwin", GOARCH: "arm64",
		Get: recordGet(fakeGH(t, tarGz, sha, false), &urls)}
	res, err := in.Install("gitleaks@latest")
	if err != nil {
		t.Fatalf("@latest 安裝失敗: %v", err)
	}

	if !contains(urls, latestURL) {
		t.Errorf("@latest 應走 latest 端點 實際請求 %v", urls)
	}
	if res.Pinned {
		t.Error("@latest 應解除釘選")
	}
	if entry := readLock(dir)["gitleaks"]; entry.Pinned {
		t.Errorf("@latest 後 lock 不應再釘選 得 %+v", entry)
	}
}

func TestInstallUnknownVersion(t *testing.T) {
	tarGz, sha := buildGitleaksTarGz(t, "REAL-GITLEAKS")

	in := &Installer{DestDir: t.TempDir(), GOOS: "darwin", GOARCH: "arm64",
		Get: fakeGH(t, tarGz, sha, false)}
	if _, err := in.Install("gitleaks@9.99.9"); err == nil {
		t.Error("不存在的版本應回錯")
	}
}

func TestInstallUnsupportedEngine(t *testing.T) {
	in := &Installer{DestDir: t.TempDir(), GOOS: "darwin", GOARCH: "arm64", Get: fakeGH(t, nil, "", false)}
	if _, err := in.Install("semgrep"); err == nil {
		t.Error("semgrep 不支援自動安裝應回錯")
	}
}

/*
TestInstallPinnedIntegration 真實端到端 走 GitHub tag 端點下載釘選版本
需網路 預設略過 以 VIGILA_NET_TEST=1 啟用 DestDir 用暫存目錄不動真實 managed 目錄
*/
func TestInstallPinnedIntegration(t *testing.T) {
	if os.Getenv("VIGILA_NET_TEST") != "1" {
		t.Skip("設 VIGILA_NET_TEST=1 以啟用真實網路整合測試")
	}
	dir := t.TempDir()
	in := &Installer{DestDir: dir, GOOS: runtime.GOOS, GOARCH: runtime.GOARCH, Get: httpGet}
	res, err := in.Install("gitleaks@8.18.4")
	if err != nil {
		t.Fatalf("釘選安裝 gitleaks@8.18.4 失敗: %v", err)
	}
	if res.Version != "8.18.4" || !res.Pinned {
		t.Errorf("應安裝並釘選 8.18.4 得 version=%q pinned=%v", res.Version, res.Pinned)
	}
	if entry := readLock(dir)["gitleaks"]; !entry.Pinned || entry.Version != "8.18.4" {
		t.Errorf("lock 應記錄釘選 8.18.4 得 %+v", entry)
	}
}

/* TestNewInstaller 確認預設安裝器欄位齊備 */
func TestNewInstaller(t *testing.T) {
	in := NewInstaller()
	if in.GOOS == "" || in.GOARCH == "" {
		t.Error("GOOS/GOARCH 應由 runtime 填入")
	}
	if in.Get == nil {
		t.Error("Get 應預設為 httpGet")
	}
	if in.TrustedRoot == nil {
		t.Error("TrustedRoot 應預設為 fetchTrustedRoot")
	}
}
