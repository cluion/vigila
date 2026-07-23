package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"testing/fstest"
	"time"

	"github.com/go-chi/chi/v5"
)

/* TestMountSPA 深層路由 fallback 到 index 靜態檔直出 API 前綴不攔截 */
func TestMountSPA(t *testing.T) {
	distFS := fstest.MapFS{
		"index.html": {Data: []byte("<html>app</html>")},
		"app.js":     {Data: []byte("console.log(1)")},
	}
	r := chi.NewRouter()
	MountSPA(r, distFS, "/api")

	t.Run("深層路由回 index", func(t *testing.T) {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/scans/abc", nil))
		if rec.Code != http.StatusOK || !containsSub(rec.Body.String(), "app") {
			t.Errorf("深層路由應 fallback index 得 %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("存在的靜態檔直出", func(t *testing.T) {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/app.js", nil))
		if rec.Code != http.StatusOK || !containsSub(rec.Body.String(), "console.log") {
			t.Errorf("靜態檔應直出 得 %d %s", rec.Code, rec.Body.String())
		}
	})

	t.Run("API 前綴不走 SPA fallback", func(t *testing.T) {
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/whatever", nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("API 前綴應回 404 實際 %d", rec.Code)
		}
	})
}

/* TestSSEStream 涵蓋 SSE 連線 connected 事件 廣播事件 與 context 取消收線 */
func TestSSEStream(t *testing.T) {
	srv, _ := newTestServer(t)
	broker := srv.Broker()

	ctx, cancel := context.WithCancel(context.Background())
	req := httptest.NewRequest(http.MethodGet, "/api/events", nil).WithContext(ctx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		broker.ServeHTTP(rec, req)
		close(done)
	}()

	/* 等客戶端註冊完成再廣播 */
	registered := false
	for i := 0; i < 200; i++ {
		broker.mu.RLock()
		n := len(broker.clients)
		broker.mu.RUnlock()
		if n > 0 {
			registered = true
			break
		}
		time.Sleep(time.Millisecond)
	}
	if !registered {
		cancel()
		<-done
		t.Fatal("SSE 客戶端未在時限內註冊")
	}

	broker.Publish(Event{Type: "scan_completed", Data: map[string]string{"id": "s1"}})
	time.Sleep(20 * time.Millisecond)
	cancel()
	<-done

	body := rec.Body.String()
	if !containsSub(body, "event: connected") {
		t.Errorf("應送出 connected 事件 實際 %s", body)
	}
	if !containsSub(body, "scan_completed") {
		t.Errorf("應送出廣播的事件 實際 %s", body)
	}
}
