package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"testing"
)

func TestParseChecksum(t *testing.T) {
	/* 標準 sha256sum 格式 <hash>  <檔名> */
	data := []byte(
		"aaa111  gitleaks_8.30.1_linux_amd64.tar.gz\n" +
			"b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5  gitleaks_8.30.1_darwin_arm64.tar.gz\n" +
			"ccc333  gitleaks_8.30.1_windows_amd64.zip\n",
	)

	t.Run("找到對應檔名的 sha256", func(t *testing.T) {
		got, err := parseChecksum(data, "gitleaks_8.30.1_darwin_arm64.tar.gz")
		if err != nil {
			t.Fatalf("預期成功 得到錯誤: %v", err)
		}
		want := "b40ab0ae55c505963e365f271a8d3846efbc170aa17f2607f13df610a9aeb6a5"
		if got != want {
			t.Errorf("sha256 = %q 預期 %q", got, want)
		}
	})

	t.Run("找不到檔名時回錯", func(t *testing.T) {
		if _, err := parseChecksum(data, "no-such-asset.tar.gz"); err == nil {
			t.Error("找不到對應檔名應回錯")
		}
	})
}

func TestExtractBinaryTarGz(t *testing.T) {
	/* 組一個含 LICENSE 與 gitleaks 的 tar.gz 驗證只取出指定 binary */
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	files := map[string]string{
		"LICENSE":  "mit",
		"gitleaks": "BINARY-CONTENT",
	}
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0o755, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()

	got, err := extractBinary(buf.Bytes(), "tar.gz", "gitleaks")
	if err != nil {
		t.Fatalf("解壓失敗: %v", err)
	}
	if string(got) != "BINARY-CONTENT" {
		t.Errorf("取出內容 = %q 預期 BINARY-CONTENT", got)
	}
}

func TestExtractBinaryZip(t *testing.T) {
	/* nuclei 等以 zip 發佈 */
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range map[string]string{"README.md": "readme", "nuclei": "NUCLEI-BIN"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	zw.Close()

	got, err := extractBinary(buf.Bytes(), "zip", "nuclei")
	if err != nil {
		t.Fatalf("解壓 zip 失敗: %v", err)
	}
	if string(got) != "NUCLEI-BIN" {
		t.Errorf("取出內容 = %q 預期 NUCLEI-BIN", got)
	}
}

func TestExtractBinaryRaw(t *testing.T) {
	/* osv-scanner 等直接發佈裸 binary 無壓縮 raw 格式原樣回傳 */
	got, err := extractBinary([]byte("OSV-RAW-BINARY"), "raw", "osv-scanner")
	if err != nil {
		t.Fatalf("raw 取出失敗: %v", err)
	}
	if string(got) != "OSV-RAW-BINARY" {
		t.Errorf("raw 內容 = %q 預期 OSV-RAW-BINARY", got)
	}
}

func TestFindChecksums(t *testing.T) {
	t.Run("goreleaser checksums.txt 排除簽章", func(t *testing.T) {
		rel := releaseWithAssets(
			asset{"grype_checksums.txt.sig", "u-sig"},
			asset{"grype_checksums.txt", "u-txt"},
		)
		name, url, err := findChecksums(rel)
		if err != nil || url != "u-txt" || name != "grype_checksums.txt" {
			t.Errorf("應取 checksums.txt 得 name=%q url=%q err %v", name, url, err)
		}
	})

	t.Run("osv-scanner SHA256SUMS 無副檔名", func(t *testing.T) {
		rel := releaseWithAssets(
			asset{"osv-scanner_linux_amd64", "u-bin"},
			asset{"osv-scanner_SHA256SUMS", "u-sums"},
		)
		name, url, err := findChecksums(rel)
		if err != nil || url != "u-sums" || name != "osv-scanner_SHA256SUMS" {
			t.Errorf("應取 SHA256SUMS 得 name=%q url=%q err %v", name, url, err)
		}
	})

	t.Run("無 checksums 檔回錯", func(t *testing.T) {
		rel := releaseWithAssets(asset{"osv-scanner_linux_amd64", "u-bin"})
		if _, _, err := findChecksums(rel); err == nil {
			t.Error("無 checksums 應回錯")
		}
	})
}

/* asset 為測試用 release 附檔 name 與下載連結 */
type asset struct{ name, url string }

/* releaseWithAssets 以指定附檔組出 ghRelease 便於測試 findChecksums findAsset */
func releaseWithAssets(assets ...asset) *ghRelease {
	rel := &ghRelease{}
	for _, a := range assets {
		rel.Assets = append(rel.Assets, struct {
			Name string `json:"name"`
			URL  string `json:"browser_download_url"`
		}{Name: a.name, URL: a.url})
	}
	return rel
}

func TestExtractBinaryNotFound(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	tw.WriteHeader(&tar.Header{Name: "OTHER", Mode: 0o644, Size: 1})
	tw.Write([]byte("x"))
	tw.Close()
	gz.Close()

	if _, err := extractBinary(buf.Bytes(), "tar.gz", "gitleaks"); err == nil {
		t.Error("壓縮檔內找不到指定 binary 應回錯")
	}
}
