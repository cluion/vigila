package upload

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

/* makeZip 在記憶體建構一個 zip 含給定的 name->content 檔案 */
func makeZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	zw := zip.NewWriter(buf)
	for name, content := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

/* makeTarGz 在記憶體建構一個 tar.gz 含給定的 name->content 檔案 */
func makeTarGz(t *testing.T, files map[string]string) []byte {
	t.Helper()
	buf := &bytes.Buffer{}
	gw := gzip.NewWriter(buf)
	tw := tar.NewWriter(gw)
	for name, content := range files {
		hdr := &tar.Header{
			Name: name,
			Mode: 0o640,
			Size: int64(len(content)),
		}
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

/* TestExtractZip 正常 zip 解壓後檔案內容正確 */
func TestExtractZip(t *testing.T) {
	dest := t.TempDir()
	data := makeZip(t, map[string]string{
		"app/main.go": "package main",
		"README.md":   "# myapp",
	})

	if err := ExtractArchive(data, "myapp.zip", dest); err != nil {
		t.Fatalf("解壓 zip 失敗: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "app", "main.go"))
	if err != nil {
		t.Fatalf("讀取解壓檔失敗: %v", err)
	}
	if string(got) != "package main" {
		t.Errorf("main.go 內容 = %q 預期 %q", got, "package main")
	}
}

/* TestExtractTarGz 正常 tar.gz 解壓後檔案內容正確 */
func TestExtractTarGz(t *testing.T) {
	dest := t.TempDir()
	data := makeTarGz(t, map[string]string{
		"src/index.ts": "export {};",
	})

	if err := ExtractArchive(data, "app.tar.gz", dest); err != nil {
		t.Fatalf("解壓 tar.gz 失敗: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(dest, "src", "index.ts"))
	if err != nil {
		t.Fatalf("讀取解壓檔失敗: %v", err)
	}
	if string(got) != "export {};" {
		t.Errorf("index.ts 內容 = %q 預期 %q", got, "export {};")
	}
}

/* TestExtractTgzExtension .tgz 副檔名也應走 tar.gz 流程 */
func TestExtractTgzExtension(t *testing.T) {
	dest := t.TempDir()
	data := makeTarGz(t, map[string]string{"a.txt": "hello"})

	if err := ExtractArchive(data, "app.tgz", dest); err != nil {
		t.Fatalf("解壓 .tgz 失敗: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "a.txt"))
	if err != nil {
		t.Fatalf("讀取解壓檔失敗: %v", err)
	}
	if string(got) != "hello" {
		t.Errorf("a.txt 內容 = %q 預期 %q", got, "hello")
	}
}

/* TestExtractZipSlip 含 ../ 的 entry 應被拒絕 不可越界寫到 dest 之外 */
func TestExtractZipSlip(t *testing.T) {
	dest := t.TempDir()
	/* 攻擊 payload 嘗試寫到 dest 上層的 evil.txt */
	data := makeZip(t, map[string]string{"../evil.txt": "pwned"})

	err := ExtractArchive(data, "evil.zip", dest)
	if err == nil {
		t.Fatal("zip slip 壓縮包應被拒絕")
	}

	/* 確認 dest 上層確實沒有被寫入 evil.txt */
	parent := filepath.Dir(dest)
	if _, err := os.Stat(filepath.Join(parent, "evil.txt")); !os.IsNotExist(err) {
		t.Fatal("evil.txt 不應出現在 dest 上層 zip slip 防護失效")
	}
}

/* TestExtractTarSlip tar.gz 含絕對路徑或 ../ 也應被拒絕 */
func TestExtractTarSlip(t *testing.T) {
	dest := t.TempDir()
	/* 直接建構含 ../ 的 tar.gz makeTarGz 不支援惡意路徑 故手動建構 */
	buf := &bytes.Buffer{}
	gw := gzip.NewWriter(buf)
	tw := tar.NewWriter(gw)
	hdr := &tar.Header{Name: "../../evil.txt", Mode: 0o640, Size: 6}
	if err := tw.WriteHeader(hdr); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("pwned")); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gw.Close()

	err := ExtractArchive(buf.Bytes(), "evil.tar.gz", dest)
	if err == nil {
		t.Fatal("tar slip 壓縮包應被拒絕")
	}
}

/* TestExtractUnsupportedFormat 非壓縮包格式應回 ErrUnsupportedFormat */
func TestExtractUnsupportedFormat(t *testing.T) {
	dest := t.TempDir()
	err := ExtractArchive([]byte("plain text"), "readme.txt", dest)
	if !errors.Is(err, ErrUnsupportedFormat) {
		t.Errorf("不支援格式應回 ErrUnsupportedFormat 實際 %v", err)
	}
}

/* TestExtractDecompressionBomb 解壓累計超過上限應中止 */
func TestExtractDecompressionBomb(t *testing.T) {
	dest := t.TempDir()
	/* 造一個單檔超過 MaxUncompressed 的 zip 應在解壓時中止 */
	big := strings.Repeat("A", MaxUncompressed+1)
	data := makeZip(t, map[string]string{"huge.txt": big})

	err := ExtractArchive(data, "bomb.zip", dest)
	if err == nil {
		t.Fatal("解壓炸彈應被中止")
	}
}
