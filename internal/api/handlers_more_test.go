package api

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

/* doReq 對 server 發請求回 recorder 供狀態與 body 檢查 */
func doReq(t *testing.T, srv *Server, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(method, path, nil))
	return rec
}

/* TestDeleteScan 刪除 scan 後應查不到 */
func TestDeleteScan(t *testing.T) {
	srv, q := newTestServer(t)
	seedProject(t, q, "p1")
	seedScan(t, q, "s1", "p1", "/tmp/app")

	if rec := doReq(t, srv, http.MethodDelete, "/api/scans/s1"); rec.Code != http.StatusOK {
		t.Fatalf("刪除 scan 狀態 = %d 預期 200 body=%s", rec.Code, rec.Body.String())
	}
	if rec := doReq(t, srv, http.MethodGet, "/api/scans/s1"); rec.Code != http.StatusNotFound {
		t.Errorf("刪除後查詢應回 404 實際 %d", rec.Code)
	}
}

/* TestListScanRuns 列出 scan 的 engine runs */
func TestListScanRuns(t *testing.T) {
	srv, q := newTestServer(t)
	seedProject(t, q, "p1")
	seedScan(t, q, "s1", "p1", "/tmp/app")
	seedRun(t, q, "run1", "s1")

	rec := doReq(t, srv, http.MethodGet, "/api/scans/s1/runs")
	if rec.Code != http.StatusOK {
		t.Fatalf("列 runs 狀態 = %d 預期 200 body=%s", rec.Code, rec.Body.String())
	}
	if !containsSub(rec.Body.String(), "run1") {
		t.Errorf("回應應含 run1 實際 %s", rec.Body.String())
	}
}

/* TestListProjects 列出專案 */
func TestListProjects(t *testing.T) {
	srv, q := newTestServer(t)
	seedProject(t, q, "p1")

	rec := doReq(t, srv, http.MethodGet, "/api/projects")
	if rec.Code != http.StatusOK {
		t.Fatalf("列 projects 狀態 = %d 預期 200 body=%s", rec.Code, rec.Body.String())
	}
	if !containsSub(rec.Body.String(), "p1") {
		t.Errorf("回應應含 p1 實際 %s", rec.Body.String())
	}
}

/* containsSub 簡易子字串檢查 供回應內容斷言 */
func containsSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
