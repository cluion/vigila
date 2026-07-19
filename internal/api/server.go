// Package api 為 Web API 層 提供 REST 與 SSE
//
// 使用 chi router 與 net/http 完全相容
// 前端 SPA 靜態檔透過 embed 內嵌
package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	"github.com/cluion/vigila/internal/store/sqlc"
)

/* Server 為 Web API 伺服器 */
type Server struct {
	db     *sql.DB
	q      *sqlc.Queries
	broker *Broker
	mux    *chi.Mux
}

/* New 建立 Server 需傳入 DB */
func New(db *sql.DB) *Server {
	q := sqlc.New(db)
	broker := NewBroker()

	s := &Server{
		db:     db,
		q:      q,
		broker: broker,
	}

	r := chi.NewRouter()
	r.Use(middleware.Logger)
	r.Use(middleware.Recoverer)
	r.Use(middleware.RequestID)

	/* REST API */
	r.Route("/api", func(r chi.Router) {
		r.Get("/scans", s.listScans)
		r.Post("/scans", s.startScan)
		r.Get("/scans/{id}", s.getScan)
		r.Delete("/scans/{id}", s.deleteScan)
		r.Get("/scans/{id}/findings", s.listScanFindings)
		r.Get("/scans/{id}/runs", s.listScanRuns)
		r.Get("/scans/{id}/sbom", s.getScanSBOM)
		r.Get("/scans/{id}/sbom/diff/{other}", s.getScanSBOMDiff)
		r.Get("/scans/{id}/diff/{other}", s.scanDiff)
		r.Get("/findings/{id}", s.getFinding)
		r.Patch("/findings/{id}", s.updateFindingStatus)
		r.Get("/projects", s.listProjects)
		r.Get("/projects/{id}/trends", s.trends)
		r.Get("/stats", s.stats)
		r.Get("/profiles", s.listProfiles)
		r.Get("/engines", s.listEngines)
		r.Post("/engines/{name}/docker", s.setEngineDocker)
	})

	/* SSE 掃描進度事件 */
	r.Get("/api/events", s.broker.ServeHTTP)

	s.mux = r
	return s
}

/* MountSPA 掛載前端 SPA 靜態檔 */
func (s *Server) MountSPA(distFS fs.FS) {
	MountSPA(s.mux, distFS, "/api/")
}

/* Broker 取得事件 broker 供 orchestrator 推播 */
func (s *Server) Broker() *Broker {
	return s.broker
}

/* Handler 回傳底層 http.Handler */
func (s *Server) Handler() http.Handler {
	return s.mux
}

/* writeJSON 回傳 JSON 回應 */
func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

/* writeError 回傳錯誤 JSON */
func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

/* parseLimitOffset 解析分頁參數 預設 limit 50 offset 0 */
func parseLimitOffset(r *http.Request) (int64, int64) {
	limit := 50
	offset := 0
	if v := r.URL.Query().Get("limit"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 500 {
			limit = n
		}
	}
	if v := r.URL.Query().Get("offset"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			offset = n
		}
	}
	return int64(limit), int64(offset)
}

/* scanDTO 為 API 回傳的 scan 物件 含 project 名稱 */
type scanDTO struct {
	sqlc.Scan
	ProjectName string `json:"project_name"`
}

/* scanDetailDTO 為單一 scan 詳情 含 engine_runs 摘要 */
type scanDetailDTO struct {
	sqlc.Scan
	ProjectName string           `json:"project_name"`
	EngineRuns  []sqlc.EngineRun `json:"engine_runs"`
}

/* ensureCtx 從 request 取得 context */
func ensureCtx(r *http.Request) context.Context {
	return r.Context()
}
