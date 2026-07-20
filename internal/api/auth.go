package api

import (
	"crypto/subtle"
	"net/http"
	"strings"
)

/*
	authMiddleware 可選的 token 認證

authToken 為空時完全放行（本機單人預設情境 行為不變）
設定後所有 /api 請求須帶對應 token 否則回 401
  - 一般請求以 Authorization: Bearer <token> 標頭
  - SSE EventSource 無法設標頭 允許以 ?token=<token> query 參數

以 constant-time 比對避免時序側信道
*/
func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if s.authToken == "" {
			next.ServeHTTP(w, r)
			return
		}
		if constantTimeMatch(extractToken(r), s.authToken) {
			next.ServeHTTP(w, r)
			return
		}
		writeError(w, http.StatusUnauthorized, "需要有效的存取 token")
	})
}

/* extractToken 從 Authorization Bearer 標頭或 token query 取出 token */
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimSpace(strings.TrimPrefix(h, "Bearer "))
	}
	/* EventSource 無法帶自訂標頭 故允許 query 參數 */
	return r.URL.Query().Get("token")
}

/* constantTimeMatch 定時比對兩字串 相等回 true */
func constantTimeMatch(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
