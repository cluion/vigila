// Package engine 負責引擎的自動安裝 下載官方 binary 到 managed 目錄
package engine

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"strings"
)

/*
	parseChecksum 從 checksums.txt 找出指定 asset 的 sha256

格式為標準 sha256sum 每行 <hash>  <檔名>
*/
func parseChecksum(data []byte, assetName string) (string, error) {
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == assetName {
			return fields[0], nil
		}
	}
	return "", fmt.Errorf("checksums 檔中找不到 %s", assetName)
}

/* formatFromAsset 由 asset 檔名副檔名推導壓縮格式 .zip 為 zip 其餘 tar.gz */
func formatFromAsset(name string) string {
	if strings.HasSuffix(name, ".zip") {
		return "zip"
	}
	return "tar.gz"
}

/*
	extractBinary 從壓縮檔取出指定名稱的 binary

支援 tar.gz 與 zip 只回傳 binName 對應檔案的內容 windows 檔內為 binName.exe
壓縮檔內可能含 LICENSE README 等其他檔案 一律略過
*/
func extractBinary(archive []byte, format, binName string) ([]byte, error) {
	switch format {
	case "tar.gz":
		return extractTarGz(archive, binName)
	case "zip":
		return extractZip(archive, binName)
	default:
		return nil, fmt.Errorf("不支援的壓縮格式 %s", format)
	}
}

/* matchesBinary 判斷壓縮檔項目是否為目標 binary 相容 windows 的 .exe */
func matchesBinary(entryName, binName string) bool {
	base := baseName(entryName)
	return base == binName || base == binName+".exe"
}

/* extractTarGz 從 tar.gz 取出指定 binary */
func extractTarGz(archive []byte, binName string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, fmt.Errorf("開啟 gzip 失敗: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("讀取 tar 失敗: %w", err)
		}
		if matchesBinary(hdr.Name, binName) {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("壓縮檔中找不到 %s", binName)
}

/* extractZip 從 zip 取出指定 binary */
func extractZip(archive []byte, binName string) ([]byte, error) {
	zr, err := zip.NewReader(bytes.NewReader(archive), int64(len(archive)))
	if err != nil {
		return nil, fmt.Errorf("開啟 zip 失敗: %w", err)
	}
	for _, f := range zr.File {
		if matchesBinary(f.Name, binName) {
			rc, err := f.Open()
			if err != nil {
				return nil, fmt.Errorf("開啟 zip 內檔案失敗: %w", err)
			}
			defer rc.Close()
			return io.ReadAll(rc)
		}
	}
	return nil, fmt.Errorf("壓縮檔中找不到 %s", binName)
}

/* baseName 取路徑最後一段 壓縮檔內 binary 可能帶目錄前綴 */
func baseName(name string) string {
	name = strings.TrimSuffix(name, "/")
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		return name[i+1:]
	}
	return name
}
