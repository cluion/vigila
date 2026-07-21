// Package upload 處理上傳壓縮包的解壓 將 zip / tar.gz 來源安全解到目標目錄
//
// 安全考量
//   - zip slip 每個 entry 的目標路徑驗證仍在 dest 內 拒絕 ../ 越界
//   - 解壓炸彈 追蹤累積解壓位元組 超過 MaxUncompressed 中止
package upload

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

/*
	MaxUncompressed 為解壓後累積位元組上限

壓縮包解壓後總大小超過此值視為解壓炸彈 中止解壓
500MB 涵蓋絕大多數源碼專案 同時防止惡意高壓縮比壓縮包耗盡磁碟
*/
const MaxUncompressed = 500 << 20

/*
	ExtractArchive 依檔名副檔名分派解壓 把壓縮包內容解到 dest 目錄

支援 .zip .tar.gz .tgz 三種常見源碼壓縮包格式 其餘回 ErrUnsupportedFormat
解壓過程強制 zip slip 與解壓炸彈防護
*/
func ExtractArchive(data []byte, filename string, dest string) error {
	switch formatOf(filename) {
	case "zip":
		return extractZip(data, dest)
	case "tar.gz":
		return extractTarGz(data, dest)
	default:
		return ErrUnsupportedFormat
	}
}

/* formatOf 由檔名副檔名推導壓縮格式 不支援回空字串 */
func formatOf(filename string) string {
	name := strings.ToLower(filename)
	switch {
	case strings.HasSuffix(name, ".zip"):
		return "zip"
	case strings.HasSuffix(name, ".tar.gz"), strings.HasSuffix(name, ".tgz"):
		return "tar.gz"
	default:
		return ""
	}
}

/* ErrUnsupportedFormat 為不支援的壓縮格式 */
var ErrUnsupportedFormat = fmt.Errorf("不支援的壓縮格式 僅接受 .zip .tar.gz .tgz")

/*
	safeJoin 把 entry 名稱接到 dest 下 並驗證結果未越界

zip slip 防護 若 entry 名含 ../ 段或為絕對路徑 導致目標落在 dest 之外 回錯拒絕整個壓縮包
不做靜默改寫 一個越界 entry 即視為惡意壓縮包 中止解壓
*/
func safeJoin(dest, name string) (string, error) {
	if name == "" {
		return "", fmt.Errorf("壓縮檔含空路徑項目 已拒絕")
	}
	/* 絕對路徑（Windows C:\ 或 Unix /）直接拒絕 */
	if filepath.IsAbs(name) {
		return "", fmt.Errorf("壓縮檔含絕對路徑 %q 已拒絕", name)
	}
	/* 逐段檢查 任何 .. 段都會越界 拒絕 */
	parts := strings.Split(filepath.ToSlash(name), "/")
	for _, p := range parts {
		if p == ".." {
			return "", fmt.Errorf("壓縮檔含越界路徑 %q 已拒絕", name)
		}
	}
	full := filepath.Join(dest, filepath.FromSlash(name))
	/* 再以 Rel 雙重保險 確認結果仍在 dest 內 */
	rel, err := filepath.Rel(dest, full)
	if err != nil || strings.HasPrefix(rel, "..") || rel == ".." {
		return "", fmt.Errorf("壓縮檔含越界路徑 %q 已拒絕", name)
	}
	return full, nil
}

/*
	extractZip 解 zip 到 dest

逐 entry 驗證路徑安全 目錄建立目錄 檔案寫入並追蹤累積大小
*/
func extractZip(data []byte, dest string) error {
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return fmt.Errorf("開啟 zip 失敗: %w", err)
	}

	var total int64
	for _, f := range zr.File {
		full, err := safeJoin(dest, f.Name)
		if err != nil {
			return err
		}

		if f.FileInfo().IsDir() {
			if err := mkdirAll(full); err != nil {
				return err
			}
			continue
		}

		if err := mkdirAll(filepath.Dir(full)); err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return fmt.Errorf("開啟 zip 內檔案 %s 失敗: %w", f.Name, err)
		}
		n, err := writeFileLimited(full, rc, MaxUncompressed-total)
		_ = rc.Close()
		if err != nil {
			return err
		}
		total += n
		if total > MaxUncompressed {
			return fmt.Errorf("解壓後總大小超過 %d MB 中止", MaxUncompressed>>20)
		}
	}
	return nil
}

/*
	extractTarGz 解 tar.gz 到 dest

gzip 解外層 tar 逐 entry 讀 取代 zip.File 的 tar.Header 流程
路徑安全與大小限制同 extractZip
*/
func extractTarGz(data []byte, dest string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("開啟 gzip 失敗: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("讀取 tar 失敗: %w", err)
		}

		full, err := safeJoin(dest, hdr.Name)
		if err != nil {
			return err
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := mkdirAll(full); err != nil {
				return err
			}
		case tar.TypeReg:
			if err := mkdirAll(filepath.Dir(full)); err != nil {
				return err
			}
			n, err := writeFileLimited(full, tr, MaxUncompressed-total)
			if err != nil {
				return err
			}
			total += n
			if total > MaxUncompressed {
				return fmt.Errorf("解壓後總大小超過 %d MB 中止", MaxUncompressed>>20)
			}
		default:
			/* 跳過 symlink hardlink fifo 等非普通檔案 避免安全風險 */
		}
	}
	return nil
}
