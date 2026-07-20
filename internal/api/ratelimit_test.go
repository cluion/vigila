package api

import (
	"testing"
	"time"
)

/* TestRateLimiterBurstThenRefill 突發用完應擋下 隨時間補充後再放行 */
func TestRateLimiterBurstThenRefill(t *testing.T) {
	/* 每分鐘 60 次（每秒 1 枚）突發 3 */
	rl := newRateLimiter(60, 3)
	now := time.Unix(1000, 0)

	/* 前 3 次用掉突發量 應全放行 */
	for i := 0; i < 3; i++ {
		if !rl.allow("1.2.3.4", now) {
			t.Fatalf("第 %d 次突發內應放行", i+1)
		}
	}
	/* 第 4 次同一瞬間 桶空 應擋下 */
	if rl.allow("1.2.3.4", now) {
		t.Error("突發用完應擋下")
	}
	/* 過 1 秒補 1 枚 應再放行一次 */
	if !rl.allow("1.2.3.4", now.Add(time.Second)) {
		t.Error("補充後應放行")
	}
}

/* TestRateLimiterPerKey 不同來源各自獨立計額 */
func TestRateLimiterPerKey(t *testing.T) {
	rl := newRateLimiter(60, 1)
	now := time.Unix(1000, 0)
	if !rl.allow("a", now) {
		t.Error("a 首次應放行")
	}
	if !rl.allow("b", now) {
		t.Error("b 首次應放行 不受 a 影響")
	}
	if rl.allow("a", now) {
		t.Error("a 桶空應擋下")
	}
}
