package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/cluion/vigila/internal/store"
	"github.com/cluion/vigila/internal/store/sqlc"
)

/* newAuthTestServer 建立啟用 token 認證的測試伺服器 */
func newAuthTestServer(t *testing.T, token string) *Server {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "test.db")})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	_ = sqlc.New(db)
	return New(db, WithAuthToken(token))
}

/* TestAuthDisabledByDefault 未設 token 時 API 應無條件放行 */
func TestAuthDisabledByDefault(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("未啟用認證應放行 實際 %d", rec.Code)
	}
}

/* TestAuthRejectsMissingAndWrongToken 啟用後 缺 token 或錯 token 應回 401 */
func TestAuthRejectsMissingAndWrongToken(t *testing.T) {
	srv := newAuthTestServer(t, "secret-token")

	/* 無 token */
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/stats", nil))
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("缺 token 應回 401 實際 %d", rec.Code)
	}

	/* 錯 token */
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("錯 token 應回 401 實際 %d", rec.Code)
	}
}

/* TestAuthAcceptsBearerAndQueryToken 正確 token 經標頭或 query 皆應放行 */
func TestAuthAcceptsBearerAndQueryToken(t *testing.T) {
	srv := newAuthTestServer(t, "secret-token")

	/* Bearer 標頭 */
	req := httptest.NewRequest(http.MethodGet, "/api/stats", nil)
	req.Header.Set("Authorization", "Bearer secret-token")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("正確 Bearer token 應放行 實際 %d", rec.Code)
	}

	/* query 參數 供 EventSource 使用 */
	rec = httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/stats?token=secret-token", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("正確 query token 應放行 實際 %d", rec.Code)
	}
}
