package api

import (
	"archive/zip"
	"bytes"
	"context"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/*
	uploadRequest 造一個 multipart/form-data 上傳請求 回傳 recorder 與請求

filePart 為壓縮包內容與檔名 engines/exclude 為選填表單欄位
*/
func uploadRequest(t *testing.T, filename string, content []byte, engines, exclude string) (*httptest.ResponseRecorder, *http.Request) {
	t.Helper()
	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(content); err != nil {
		t.Fatal(err)
	}
	if engines != "" {
		_ = mw.WriteField("engines", engines)
	}
	if exclude != "" {
		_ = mw.WriteField("exclude", exclude)
	}
	if err := mw.Close(); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/uploads/scan", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	rec := httptest.NewRecorder()
	return rec, req
}

/* zipBytes 建構記憶體 zip 含給定的 name->content 檔案 */
func zipBytes(t *testing.T, files map[string]string) []byte {
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

/* TestUploadRejectsMissingFile 缺 file 欄位應回 400 */
func TestUploadRejectsMissingFile(t *testing.T) {
	srv, _ := newTestServer(t)

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	_ = mw.Close()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/uploads/scan", body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("缺 file 欄位應回 400 實際 %d", rec.Code)
	}
}

/* TestUploadRejectsUnsupportedFormat 非壓縮包副檔名應回 400 */
func TestUploadRejectsUnsupportedFormat(t *testing.T) {
	srv, _ := newTestServer(t)

	rec, req := uploadRequest(t, "readme.txt", []byte("plain"), "", "")
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("非壓縮包應回 400 實際 %d", rec.Code)
	}
}

/* TestUploadRejectsZipSlip 含 ../ 的惡意 zip 應在解壓時被拒 400 */
func TestUploadRejectsZipSlip(t *testing.T) {
	srv, _ := newTestServer(t)

	payload := zipBytes(t, map[string]string{"../evil.txt": "pwned"})
	rec, req := uploadRequest(t, "evil.zip", payload, "", "")
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("zip slip 壓縮包應回 400 實際 %d body %s", rec.Code, rec.Body.String())
	}
}

/* TestUploadRejectsFlagLikeExclude exclude 含 - 開頭應擋下 防引數走私 */
func TestUploadRejectsFlagLikeExclude(t *testing.T) {
	srv, _ := newTestServer(t)

	payload := zipBytes(t, map[string]string{"app/main.go": "package main"})
	rec, req := uploadRequest(t, "app.zip", payload, "", "--output=/etc/passwd")
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("- 開頭的 exclude 應回 400 實際 %d body %s", rec.Code, rec.Body.String())
	}
}

/* TestUploadAcceptsValidZip 合法 zip 應回 202 並啟動掃描 */
func TestUploadAcceptsValidZip(t *testing.T) {
	srv, _ := newTestServer(t)
	scanner.Register(&uploadFakeScanner{})

	payload := zipBytes(t, map[string]string{"app/main.go": "package main"})
	rec, req := uploadRequest(t, "app.zip", payload, "", "")
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("合法 zip 應回 202 實際 %d body %s", rec.Code, rec.Body.String())
	}
}

/*
	uploadFakeScanner 為上傳測試用的假引擎 不真跑 binary

吃 path 目標 Run 回空結果 供 202 分支的背景掃描安全完成
*/
type uploadFakeScanner struct{}

func (f *uploadFakeScanner) Name() string             { return "fake-upload" }
func (f *uploadFakeScanner) Category() model.Category { return model.CategorySAST }
func (f *uploadFakeScanner) Binary() string           { return "fake-upload" }
func (f *uploadFakeScanner) VersionArgs() []string    { return []string{"--version"} }
func (f *uploadFakeScanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetPath}
}
func (f *uploadFakeScanner) InstallHint() scanner.InstallHint { return scanner.InstallHint{} }
func (f *uploadFakeScanner) CheckInstalled() error            { return nil }
func (f *uploadFakeScanner) ExitCodeIsFindings(int) bool      { return false }
func (f *uploadFakeScanner) Parse([]byte) ([]model.Finding, error) {
	return nil, nil
}
func (f *uploadFakeScanner) BuildCommand(string, scanner.Options) (string, []string) {
	return "fake-upload", nil
}
func (f *uploadFakeScanner) Run(context.Context, string, scanner.Options) (*scanner.Result, error) {
	return &scanner.Result{RawOutput: []byte("{}")}, nil
}
