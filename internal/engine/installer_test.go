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
		case "https://api.github.com/repos/gitleaks/gitleaks/releases/latest":
			return releaseJSON, 200, nil
		case assetURL:
			return body, 200, nil
		case checksumsURL:
			return checksums, 200, nil
		}
		return nil, 404, nil
	}
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

func TestInstallUnsupportedEngine(t *testing.T) {
	in := &Installer{DestDir: t.TempDir(), GOOS: "darwin", GOARCH: "arm64", Get: fakeGH(t, nil, "", false)}
	if _, err := in.Install("semgrep"); err == nil {
		t.Error("semgrep 不支援自動安裝應回錯")
	}
}
