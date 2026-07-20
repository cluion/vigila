package upload

import (
	"fmt"
	"io"
	"os"
)

/*
	mkdirAll 建立目錄 權限 0o750 與 managed 目錄慣例一致 不開放 world

封裝 os.MkdirAll 統一權限與錯誤訊息格式
*/
func mkdirAll(path string) error {
	if err := os.MkdirAll(path, 0o750); err != nil {
		return fmt.Errorf("建立目錄 %s 失敗: %w", path, err)
	}
	return nil
}

/*
	writeFileLimited 把 r 內容寫入 path 並限制最多讀 maxBytes

回傳實際寫入位元組數 供累計解壓總大小
檔案權限 0o640 原始碼檔案不需執行權 不開放 world
超過 maxBytes 回 ErrDecompressionLimit 讓呼叫端中止整個解壓
*/
func writeFileLimited(path string, r io.Reader, maxBytes int64) (int64, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o640) // #nosec G304 -- path 由 safeJoin 驗證在 dest 內
	if err != nil {
		return 0, fmt.Errorf("建立檔案 %s 失敗: %w", path, err)
	}
	defer f.Close()

	n, err := io.Copy(f, io.LimitReader(r, maxBytes+1))
	if err != nil {
		return n, fmt.Errorf("寫入檔案 %s 失敗: %w", path, err)
	}
	if n > maxBytes {
		return n, ErrDecompressionLimit
	}
	return n, nil
}

/* ErrDecompressionLimit 為單檔或累計解壓超過上限 */
var ErrDecompressionLimit = fmt.Errorf("解壓大小超過限制")
