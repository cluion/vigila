package api

import (
	"net"
	"net/http"
	"sync"
	"time"
)

/*
	rateLimiter 為每來源 IP 的權杖桶限流器

以記憶體 map 記錄各 IP 的桶 惰性補充權杖 無背景 goroutine
供團隊/暴露情境防止掃描 上傳 安裝等昂貴端點被反覆呼叫耗盡資源
本機單人情境限額寬鬆 不影響正常使用
*/
type rateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*tokenBucket
	rate    float64 // 每秒補充的權杖數
	burst   float64 // 桶容量 允許的瞬間突發量
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

/* newRateLimiter 以每分鐘上限與突發量建立限流器 */
func newRateLimiter(perMinute, burst int) *rateLimiter {
	return &rateLimiter{
		buckets: make(map[string]*tokenBucket),
		rate:    float64(perMinute) / 60.0,
		burst:   float64(burst),
	}
}

/* allow 判斷指定來源此刻是否放行 並扣一枚權杖 */
func (rl *rateLimiter) allow(key string, now time.Time) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	/* 防止不同 IP 無限增長撐爆記憶體 到上限即整批重置 */
	if len(rl.buckets) > 10000 {
		rl.buckets = make(map[string]*tokenBucket)
	}

	b, ok := rl.buckets[key]
	if !ok {
		rl.buckets[key] = &tokenBucket{tokens: rl.burst - 1, last: now}
		return true
	}

	elapsed := now.Sub(b.last).Seconds()
	b.tokens = min(rl.burst, b.tokens+elapsed*rl.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

/* middleware 將限流套用到 handler 超限回 429 */
func (rl *rateLimiter) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !rl.allow(clientIP(r), time.Now()) {
			writeError(w, http.StatusTooManyRequests, "請求過於頻繁 請稍後再試")
			return
		}
		next.ServeHTTP(w, r)
	})
}

/* clientIP 取請求來源 IP 去除連接埠 */
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
