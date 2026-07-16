package api

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

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
		Scan       scanDTO `json:"scan"`
		Findings   int64   `json:"findings"`
		Critical   int64   `json:"critical"`
		High       int64   `json:"high"`
		Medium     int64   `json:"medium"`
		Low        int64   `json:"low"`
	}

	stats := make([]scanStat, 0, len(scans))
	for _, sc := range scans {
		dto := scanDTO{Scan: sc}
		if p, err := s.q.GetProject(ctx, sc.ProjectID); err == nil {
			dto.ProjectName = p.Name
		}

		st := scanStat{Scan: dto}
		st.Findings, _ = s.q.CountFindingsByProject(ctx, sc.ProjectID)

		/* severity 分布 */
		sv, _ := s.q.CountFindingsBySeverity(ctx, sc.ProjectID)
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
