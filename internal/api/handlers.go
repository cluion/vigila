package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/scanner"
	"github.com/cluion/vigila/internal/store/sqlc"
)

/* listScans GET /api/scans?limit=&offset= */
func (s *Server) listScans(w http.ResponseWriter, r *http.Request) {
	ctx := ensureCtx(r)
	limit, offset := parseLimitOffset(r)

	scans, err := s.q.ListScans(ctx, sqlc.ListScansParams{Limit: limit, Offset: offset})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查詢 scans 失敗")
		return
	}

	/* 每個 scan 帶出 project 名稱 */
	out := make([]scanDTO, 0, len(scans))
	for _, sc := range scans {
		dto := scanDTO{Scan: sc}
		if p, err := s.q.GetProject(ctx, sc.ProjectID); err == nil {
			dto.ProjectName = p.Name
		}
		out = append(out, dto)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"scans":  out,
		"limit":  limit,
		"offset": offset,
	})
}

/* getScan GET /api/scans/{id} 含 engine_runs */
func (s *Server) getScan(w http.ResponseWriter, r *http.Request) {
	ctx := ensureCtx(r)
	id := chi.URLParam(r, "id")

	scan, err := s.q.GetScan(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "scan 不存在")
			return
		}
		writeError(w, http.StatusInternalServerError, "查詢 scan 失敗")
		return
	}

	dto := scanDetailDTO{Scan: scan}
	if p, err := s.q.GetProject(ctx, scan.ProjectID); err == nil {
		dto.ProjectName = p.Name
	}
	if runs, err := s.q.ListEngineRunsByScan(ctx, id); err == nil {
		dto.EngineRuns = runs
	}

	writeJSON(w, http.StatusOK, dto)
}

/* listScanFindings GET /api/scans/{id}/findings 依 severity 排序 */
func (s *Server) listScanFindings(w http.ResponseWriter, r *http.Request) {
	ctx := ensureCtx(r)
	id := chi.URLParam(r, "id")

	findings, err := s.q.ListFindingsByScan(ctx, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查詢 findings 失敗")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"scan_id":  id,
		"findings": findings,
		"total":    len(findings),
	})
}

/* listScanRuns GET /api/scans/{id}/runs */
func (s *Server) listScanRuns(w http.ResponseWriter, r *http.Request) {
	ctx := ensureCtx(r)
	id := chi.URLParam(r, "id")

	runs, err := s.q.ListEngineRunsByScan(ctx, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查詢 engine_runs 失敗")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"scan_id":     id,
		"engine_runs": runs,
	})
}

/* scanDiff GET /api/scans/{id}/diff/{other} 比較兩次掃描的 findings 差異 */
func (s *Server) scanDiff(w http.ResponseWriter, r *http.Request) {
	ctx := ensureCtx(r)
	fromID := chi.URLParam(r, "id")
	toID := chi.URLParam(r, "other")

	diff, err := core.Diff(ctx, s.q, fromID, toID)
	if err != nil {
		switch {
		case errors.Is(err, sql.ErrNoRows):
			writeError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, core.ErrCrossProject):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "計算掃描差異失敗")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"from":      diff.From,
		"to":        diff.To,
		"added":     diff.Added,
		"removed":   diff.Removed,
		"unchanged": diff.Unchanged,
	})
}

/* getFinding GET /api/findings/{id} */
func (s *Server) getFinding(w http.ResponseWriter, r *http.Request) {
	ctx := ensureCtx(r)
	id := chi.URLParam(r, "id")

	f, err := s.q.GetFinding(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "finding 不存在")
			return
		}
		writeError(w, http.StatusInternalServerError, "查詢 finding 失敗")
		return
	}

	writeJSON(w, http.StatusOK, f)
}

/* validFindingStatus 為 finding 允許的狀態 */
var validFindingStatus = map[string]bool{
	"open":     true,
	"resolved": true,
	"ignored":  true,
}

/* updateFindingStatus PATCH /api/findings/{id} 標記漏洞狀態 open resolved ignored */
func (s *Server) updateFindingStatus(w http.ResponseWriter, r *http.Request) {
	ctx := ensureCtx(r)
	id := chi.URLParam(r, "id")

	var req struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "請求格式錯誤")
		return
	}
	if !validFindingStatus[req.Status] {
		writeError(w, http.StatusBadRequest, "status 需為 open resolved 或 ignored")
		return
	}

	f, err := s.q.UpdateFindingStatus(ctx, sqlc.UpdateFindingStatusParams{
		Status: req.Status,
		ID:     id,
	})
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeError(w, http.StatusNotFound, "finding 不存在")
			return
		}
		writeError(w, http.StatusInternalServerError, "更新 finding 狀態失敗")
		return
	}

	writeJSON(w, http.StatusOK, f)
}

/* listProjects GET /api/projects */
func (s *Server) listProjects(w http.ResponseWriter, r *http.Request) {
	ctx := ensureCtx(r)
	limit, offset := parseLimitOffset(r)

	projects, err := s.q.ListProjects(ctx, sqlc.ListProjectsParams{Limit: limit, Offset: offset})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "查詢 projects 失敗")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"projects": projects,
	})
}

/* stats GET /api/stats 全域統計 最近 scans 與 severity 分布 */
func (s *Server) stats(w http.ResponseWriter, r *http.Request) {
	ctx := ensureCtx(r)

	/* 最近 10 個 scan */
	scans, _ := s.q.ListScans(ctx, sqlc.ListScansParams{Limit: 10, Offset: 0})

	type scanStat struct {
		Scan     scanDTO `json:"scan"`
		Findings int64   `json:"findings"`
		Critical int64   `json:"critical"`
		High     int64   `json:"high"`
		Medium   int64   `json:"medium"`
		Low      int64   `json:"low"`
	}

	stats := make([]scanStat, 0, len(scans))
	for _, sc := range scans {
		dto := scanDTO{Scan: sc}
		if p, err := s.q.GetProject(ctx, sc.ProjectID); err == nil {
			dto.ProjectName = p.Name
		}

		st := scanStat{Scan: dto}
		st.Findings, _ = s.q.CountFindingsByScan(ctx, sc.ID)

		/* severity 分布 以單次 scan 為維度 */
		sv, _ := s.q.CountFindingsBySeverityByScan(ctx, sc.ID)
		for _, row := range sv {
			switch row.Severity {
			case "CRITICAL":
				st.Critical = row.Count
			case "HIGH":
				st.High = row.Count
			case "MEDIUM":
				st.Medium = row.Count
			case "LOW":
				st.Low = row.Count
			}
		}
		stats = append(stats, st)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"recent_scans": stats,
	})
}

/* startScanRequest 為 POST /api/scans 的請求 body */
type startScanRequest struct {
	Target  string `json:"target"`
	Engine  string `json:"engine"`  // 單一引擎 或 all
	Profile string `json:"profile"` // profile 名
}

/* startScan POST /api/scans 從 Web 觸發掃描 背景執行 透過 SSE 推播進度 */
func (s *Server) startScan(w http.ResponseWriter, r *http.Request) {
	var req startScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "請求格式錯誤")
		return
	}
	if req.Target == "" {
		writeError(w, http.StatusBadRequest, "target 必填")
		return
	}

	orch := core.New(s.q).WithTriggerSource("web").WithEvent(func(eventType string, data interface{}) {
		s.broker.Publish(Event{Type: eventType, Data: data})
	})

	ctx := context.Background()

	/* 決定掃描方式 profile 優先 再來 all 再來單一 */
	var run func() (*core.ScanResult, error)
	switch {
	case req.Profile != "":
		run = func() (*core.ScanResult, error) {
			return orch.RunProfile(ctx, req.Profile, req.Target, scanner.Options{})
		}
	case req.Engine == "all" || req.Engine == "":
		run = func() (*core.ScanResult, error) {
			return orch.RunMultiple(ctx, scanner.All(), req.Target, scanner.Options{})
		}
	default:
		sc, err := scanner.Get(req.Engine)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		run = func() (*core.ScanResult, error) {
			return orch.RunSingle(ctx, sc, req.Target, scanner.Options{})
		}
	}

	/* 背景執行 立即回應 202 */
	go func() {
		if _, err := run(); err != nil {
			log.Printf("web 觸發掃描 %s 失敗: %v", req.Target, err)
		}
	}()

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"message": "掃描已啟動 進度請訂閱 /api/events",
		"target":  req.Target,
	})
}

/* listProfiles GET /api/profiles 列出內建 profile */
func (s *Server) listProfiles(w http.ResponseWriter, r *http.Request) {
	/* core.ProfileNames 回傳逗號分隔字串 這裡直接回傳 */
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"profiles": core.ProfileNames(),
	})
}

/* listEngines GET /api/engines 列出已註冊引擎 */
func (s *Server) listEngines(w http.ResponseWriter, r *http.Request) {
	engines := scanner.All()
	out := make([]map[string]string, 0, len(engines))
	for _, e := range engines {
		out = append(out, map[string]string{
			"name":     e.Name(),
			"category": string(e.Category()),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"engines": out,
	})
}
