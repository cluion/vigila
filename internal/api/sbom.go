package api

import (
	"database/sql"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/sbom"
)

/*
	getScanSBOM GET /api/scans/{id}/sbom

回傳該 scan 的 SBOM 套件清單 由後端解析 CycloneDX 前端直接渲染表格
無 SBOM 時 available 為 false packages 為空 避免前端錯誤處理
*/
func (s *Server) getScanSBOM(w http.ResponseWriter, r *http.Request) {
	ctx := ensureCtx(r)
	id := chi.URLParam(r, "id")

	art, err := s.q.GetLatestSBOMByScan(ctx, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"scan_id":   id,
				"available": false,
				"packages":  []sbom.Package{},
				"total":     0,
			})
			return
		}
		writeError(w, http.StatusInternalServerError, "查詢 SBOM 失敗")
		return
	}

	/* ParsePackages 成功時恆回非 nil 切片 序列化為 [] */
	pkgs, perr := sbom.ParsePackages([]byte(art.Content))
	if perr != nil {
		writeError(w, http.StatusInternalServerError, "解析 SBOM 失敗")
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"scan_id":   id,
		"available": true,
		"engine":    art.Engine,
		"format":    art.Format,
		"packages":  pkgs,
		"total":     len(pkgs),
	})
}

/*
	getScanSBOMDiff GET /api/scans/{id}/sbom/diff/{other}

比較 {other}(舊)與 {id}(新)兩次掃描的 SBOM 套件差異 供前端供應鏈漂移檢視
兩次掃描需屬同一 project 且各自已產生 SBOM 否則回 400
*/
func (s *Server) getScanSBOMDiff(w http.ResponseWriter, r *http.Request) {
	ctx := ensureCtx(r)
	id := chi.URLParam(r, "id")
	other := chi.URLParam(r, "other")

	res, err := core.DiffSBOM(ctx, s.q, other, id)
	if err != nil {
		/* 依錯誤型別給正確狀態碼 內部錯誤脫敏 與 scanDiff 一致 */
		switch {
		case errors.Is(err, sql.ErrNoRows):
			writeError(w, http.StatusNotFound, err.Error())
		case errors.Is(err, core.ErrCrossProject), errors.Is(err, core.ErrNoSBOM):
			writeError(w, http.StatusBadRequest, err.Error())
		default:
			writeError(w, http.StatusInternalServerError, "計算 SBOM 差異失敗")
		}
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"from":       res.From,
		"to":         res.To,
		"from_total": res.FromTotal,
		"to_total":   res.ToTotal,
		"added":      res.Diff.Added,
		"removed":    res.Diff.Removed,
		"changed":    res.Diff.Changed,
		"unchanged":  res.Diff.Unchanged,
	})
}
