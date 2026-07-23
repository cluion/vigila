package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

/* postBody 對 server 發帶 body 的請求 */
func postBody(t *testing.T, srv *Server, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

/* TestGetFindingNotFound 不存在的 finding 回 404 */
func TestGetFindingNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	if rec := doReq(t, srv, http.MethodGet, "/api/findings/nope"); rec.Code != http.StatusNotFound {
		t.Errorf("不存在 finding 應回 404 實際 %d", rec.Code)
	}
}

/* TestInstallEngineNotInstallable 不支援自動安裝的引擎回 400 不觸發網路 */
func TestInstallEngineNotInstallable(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := postBody(t, srv, "/api/engines/semgrep/install", "")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("semgrep 不可自動安裝應回 400 實際 %d body=%s", rec.Code, rec.Body.String())
	}
}

/* TestSetEngineDockerEdge 非 docker-capable 與無效 body 皆回 400 */
func TestSetEngineDockerEdge(t *testing.T) {
	srv, _ := newTestServer(t)

	t.Run("非 docker-capable 引擎", func(t *testing.T) {
		rec := postBody(t, srv, "/api/engines/no-such-engine/docker", `{"enabled":true}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("非 docker-capable 應回 400 實際 %d", rec.Code)
		}
	})

	t.Run("無效 JSON body", func(t *testing.T) {
		rec := postBody(t, srv, "/api/engines/semgrep/docker", "{broken")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("無效 body 應回 400 實際 %d", rec.Code)
		}
	})
}

/* TestListScansLimitOffset 帶 limit/offset 查詢參數應正常回應 */
func TestListScansLimitOffset(t *testing.T) {
	srv, q := newTestServer(t)
	seedProject(t, q, "p1")
	seedScan(t, q, "s1", "p1", "/tmp/a")
	seedScan(t, q, "s2", "p1", "/tmp/b")

	rec := doReq(t, srv, http.MethodGet, "/api/scans?limit=1&offset=0")
	if rec.Code != http.StatusOK {
		t.Fatalf("帶分頁參數狀態 = %d 預期 200", rec.Code)
	}
	if !containsSub(rec.Body.String(), `"limit":1`) {
		t.Errorf("回應應反映 limit=1 實際 %s", rec.Body.String())
	}
}

/* TestBrokerAccessor Broker getter 不應為 nil */
func TestBrokerAccessor(t *testing.T) {
	srv, _ := newTestServer(t)
	if srv.Broker() == nil {
		t.Error("Broker() 不應為 nil")
	}
}
