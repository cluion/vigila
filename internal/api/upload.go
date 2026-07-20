package api

import (
	"context"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/scanner"
	"github.com/cluion/vigila/internal/upload"
)

/*
	MaxUploadBytes 為上傳壓縮包大小上限 100MB

在 ParseMultipartForm 前以 MaxBytesReader 包裹 body 超限直接 400
涵蓋絕大多數源碼壓縮包 防止磁碟與記憶體濫用
*/
const MaxUploadBytes = 100 << 20

/*
	uploadAndScan POST /api/uploads/scan 上傳壓縮包並掃描

	multipart/form-data 欄位
	  file     必填 壓縮包 .zip .tar.gz .tgz
	  engines  選填 逗號分隔引擎清單 非空時優先於 all
	  exclude  選填 逗號分隔排除路徑

流程 限制 body 大小 → 讀檔 → 依副檔名判定格式 → 解壓到 temp dir →
背景掃描 temp dir（複用 startScan 的 orchestrator 模式）→ goroutine 內掃完刪 temp dir
*/
func (s *Server) uploadAndScan(w http.ResponseWriter, r *http.Request) {
	/* 限制上傳大小 超過 MaxUploadBytes 在讀 body 時即觸發 */
	r.Body = http.MaxBytesReader(w, r.Body, MaxUploadBytes)
	if err := r.ParseMultipartForm(MaxUploadBytes); err != nil {
		writeError(w, http.StatusBadRequest, "上傳失敗 檔案過大或格式錯誤 上限 100MB")
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "缺少 file 欄位")
		return
	}
	defer file.Close()

	/* 副檔名白名單 非壓縮包直接拒絕 不讀內容 */
	if !isSupportedArchive(header.Filename) {
		writeError(w, http.StatusBadRequest, "僅接受 .zip .tar.gz .tgz 壓縮包")
		return
	}

	/* engines / exclude 為選填 逗號分隔 */
	excludes, err := parseCSVField(r.FormValue("exclude"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	engineNames, _ := parseCSVField(r.FormValue("engines"))

	/* 讀全部內容 ExtractArchive 吃 []byte 而非 stream 以便 zip.NewReader */
	content, err := io.ReadAll(file)
	if err != nil {
		writeError(w, http.StatusBadRequest, "讀取上傳檔失敗")
		return
	}

	/* 解壓到 temp dir 失敗即回 400 不留半成品 */
	tempDir, err := os.MkdirTemp("", "vigila-upload-*")
	if err != nil {
		writeError(w, http.StatusInternalServerError, "建立暫存目錄失敗")
		return
	}
	if err := upload.ExtractArchive(content, header.Filename, tempDir); err != nil {
		_ = os.RemoveAll(tempDir)
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	/* 組 orchestrator 與 startScan 一致 web 觸發 + SSE 進度推播
	   以壓縮包檔名作 project 名 讓重複上傳同一檔案歸於同一 project 去重與 diff 才有效 */
	orch := core.New(s.q).
		WithTriggerSource("web").
		WithProjectName(filepath.Base(header.Filename)).
		WithEvent(func(eventType string, data interface{}) {
			s.broker.Publish(Event{Type: eventType, Data: data})
		})
	ctx := context.Background()
	opts := scanner.Options{Exclude: excludes}

	/* 決定掃描方式 指定 engines 優先 否則 all for target */
	var run func() (*core.ScanResult, error)
	if len(engineNames) > 0 {
		scanners := make([]scanner.Scanner, 0, len(engineNames))
		for _, name := range engineNames {
			sc, err := scanner.GetForTarget(name, tempDir)
			if err != nil {
				_ = os.RemoveAll(tempDir)
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			scanners = append(scanners, sc)
		}
		run = func() (*core.ScanResult, error) {
			return orch.RunMultiple(ctx, scanners, tempDir, opts)
		}
	} else {
		scanners, err := scanner.AllForTarget(tempDir)
		if err != nil {
			_ = os.RemoveAll(tempDir)
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		run = func() (*core.ScanResult, error) {
			return orch.RunMultiple(ctx, scanners, tempDir, opts)
		}
	}

	/* 背景執行 掃完無論成敗立即刪 temp dir */
	go func() {
		defer func() { _ = os.RemoveAll(tempDir) }()
		if _, err := run(); err != nil {
			log.Printf("web 上傳掃描 %s 失敗: %v", header.Filename, err)
		}
	}()

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"message": "上傳成功 掃描已啟動 進度請訂閱 /api/events",
		"target":  tempDir,
	})
}

/* isSupportedArchive 判斷檔名是否為接受的壓縮包格式 */
func isSupportedArchive(filename string) bool {
	name := strings.ToLower(filename)
	return strings.HasSuffix(name, ".zip") ||
		strings.HasSuffix(name, ".tar.gz") ||
		strings.HasSuffix(name, ".tgz")
}

/*
	parseCSVField 把逗號分隔的表單欄位切成去空白的清單 並驗證排除規則

空字串回空清單 非空時逐項驗證（排除路徑防引數走私）
*/
func parseCSVField(value string) ([]string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	/* exclude 欄位需驗證 engines 欄位只是引擎名 不驗證 */
	if err := scanner.ValidateExcludes(out); err != nil {
		return nil, err
	}
	return out, nil
}
