package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

/* Event 為 SSE 推播的事件 */
type Event struct {
	Type string      // scan_started scan_completed engine_completed
	Data interface{} // 序列化為 JSON
}

/* Broker 管理 SSE 客戶端連線 並廣播事件 */
type Broker struct {
	mu      sync.RWMutex
	clients map[chan Event]struct{}
}

/* NewBroker 建立 Broker */
func NewBroker() *Broker {
	return &Broker{
		clients: make(map[chan Event]struct{}),
	}
}

/* Publish 廣播事件給所有連線客戶端 非阻塞 */
func (b *Broker) Publish(e Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.clients {
		select {
		case ch <- e:
		default: // 客戶端緩衝已滿 跳過 避免阻塞
		}
	}
}

/*
	ServeHTTP 處理 SSE 連線 GET /api/events

連線後每隔 15 秒送 heartbeat 保持連線
*/
func (b *Broker) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "不支援 streaming", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	/* 註冊客戶端 */
	ch := make(chan Event, 16)
	b.mu.Lock()
	b.clients[ch] = struct{}{}
	b.mu.Unlock()

	defer func() {
		b.mu.Lock()
		delete(b.clients, ch)
		b.mu.Unlock()
		close(ch)
	}()

	/* 通知連線成功 */
	fmt.Fprintf(w, "event: connected\ndata: {}\n\n")
	flusher.Flush()

	/* heartbeat ticker */
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	ctx := r.Context()
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-ch:
			data, _ := json.Marshal(e.Data)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, data)
			flusher.Flush()
		case <-ticker.C:
			fmt.Fprintf(w, ": heartbeat\n\n")
			flusher.Flush()
		}
	}
}
