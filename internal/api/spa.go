package api

import (
	"io/fs"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

/* MountSPA 把前端 SPA 靜態檔掛到 router 並加上 SPA fallback

深層路由刷新時回傳 index.html 讓 client-side router 接手
apiPrefix 下的路由不會被 SPA 攔截 */
func MountSPA(r chi.Router, distFS fs.FS, apiPrefix string) {
	fileServer := http.FileServer(http.FS(distFS))

	r.Get("/*", func(w http.ResponseWriter, r *http.Request) {
		/* API 與 SSE 路由不走 SPA fallback */
		if strings.HasPrefix(r.URL.Path, apiPrefix) {
			http.NotFound(w, r)
			return
		}

		/* 檢查請求的檔案是否存在 不存在則回 index.html 給 SPA router */
		cleanPath := strings.TrimPrefix(r.URL.Path, "/")
		if cleanPath != "" {
			if f, err := distFS.Open(cleanPath); err == nil {
				f.Close()
				fileServer.ServeHTTP(w, r)
				return
			}
		}

		/* fallback 到 index.html */
		r2 := r.Clone(r.Context())
		r2.URL.Path = "/"
		fileServer.ServeHTTP(w, r2)
	})
}
