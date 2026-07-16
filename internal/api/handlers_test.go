package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
	"github.com/cluion/vigila/internal/store"
	"github.com/cluion/vigila/internal/store/sqlc"
)

/* newTestServer 建立掛在暫存 SQLite 上的 API server */
func newTestServer(t *testing.T) (*Server, *sqlc.Queries) {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "test.db")})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db), sqlc.New(db)
}

/* seedScan 建立一筆 scan 供測試 */
func seedScan(t *testing.T, q *sqlc.Queries, id, projectID, target string) {
	t.Helper()
	_, err := q.CreateScan(context.Background(), sqlc.CreateScanParams{
		ID:            id,
		ProjectID:     projectID,
		Target:        target,
		ScanType:      "single",
		Status:        "completed",
		TriggerSource: "cli",
	})
	if err != nil {
		t.Fatalf("建立測試 scan 失敗: %v", err)
	}
}

/* seedFinding 建立一筆 finding 供測試 */
func seedFinding(t *testing.T, q *sqlc.Queries, id, projectID, scanID, runID, severity string) {
	t.Helper()
	_, err := q.UpsertFinding(context.Background(), sqlc.UpsertFindingParams{
		ID:          id,
		ProjectID:   projectID,
		ScanID:      scanID,
		EngineRunID: runID,
		Engine:      "fake",
		Category:    "SAST",
		RuleID:      "rule-" + id,
		Title:       "finding " + id,
		Severity:    severity,
		HashCode:    "hash-" + id,
	})
	if err != nil {
		t.Fatalf("建立測試 finding 失敗: %v", err)
	}
}

/* TestStatsCountsPerScan /api/stats 的統計應以單次 scan 為維度 而非 project 累計 */
func TestStatsCountsPerScan(t *testing.T) {
	ctx := context.Background()
	srv, q := newTestServer(t)

	p, err := q.UpsertProjectByName(ctx, sqlc.UpsertProjectByNameParams{ID: "p1", Name: "demo"})
	if err != nil {
		t.Fatalf("建立測試 project 失敗: %v", err)
	}

	/* scan1 有 2 筆 findings scan2 沒有任何 finding */
	seedScan(t, q, "scan1", p.ID, "/tmp/a")
	seedScan(t, q, "scan2", p.ID, "/tmp/b")
	run, err := q.CreateEngineRun(ctx, sqlc.CreateEngineRunParams{
		ID: "run1", ScanID: "scan1", Engine: "fake", Category: "SAST", Status: "completed",
	})
	if err != nil {
		t.Fatalf("建立測試 engine_run 失敗: %v", err)
	}
	seedFinding(t, q, "f1", p.ID, "scan1", run.ID, "HIGH")
	seedFinding(t, q, "f2", p.ID, "scan1", run.ID, "CRITICAL")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/stats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/stats 回應碼 %d", rec.Code)
	}

	var body struct {
		RecentScans []struct {
			Scan struct {
				ID string `json:"id"`
			} `json:"scan"`
			Findings int64 `json:"findings"`
			Critical int64 `json:"critical"`
			High     int64 `json:"high"`
		} `json:"recent_scans"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("解析 stats 回應失敗: %v", err)
	}

	got := map[string]struct{ findings, critical, high int64 }{}
	for _, row := range body.RecentScans {
		got[row.Scan.ID] = struct{ findings, critical, high int64 }{row.Findings, row.Critical, row.High}
	}

	if got["scan1"].findings != 2 || got["scan1"].critical != 1 || got["scan1"].high != 1 {
		t.Errorf("scan1 統計錯誤: %+v 預期 findings=2 critical=1 high=1", got["scan1"])
	}
	if got["scan2"].findings != 0 || got["scan2"].critical != 0 || got["scan2"].high != 0 {
		t.Errorf("scan2 沒有 finding 統計應全為 0 實際: %+v", got["scan2"])
	}
}

/* patchStatus 對 /api/findings/{id} 發 PATCH 回傳 recorder */
func patchStatus(t *testing.T, srv *Server, id, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPatch, "/api/findings/"+id, strings.NewReader(body))
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

/* TestUpdateFindingStatus PATCH /api/findings/{id} 可標記 open resolved ignored */
func TestUpdateFindingStatus(t *testing.T) {
	ctx := context.Background()
	srv, q := newTestServer(t)

	p, err := q.UpsertProjectByName(ctx, sqlc.UpsertProjectByNameParams{ID: "p1", Name: "demo"})
	if err != nil {
		t.Fatalf("建立測試 project 失敗: %v", err)
	}
	seedScan(t, q, "scan1", p.ID, "/tmp/a")
	run, err := q.CreateEngineRun(ctx, sqlc.CreateEngineRunParams{
		ID: "run1", ScanID: "scan1", Engine: "fake", Category: "SAST", Status: "completed",
	})
	if err != nil {
		t.Fatalf("建立測試 engine_run 失敗: %v", err)
	}
	seedFinding(t, q, "f1", p.ID, "scan1", run.ID, "HIGH")

	/* 標記 resolved */
	rec := patchStatus(t, srv, "f1", `{"status": "resolved"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("PATCH 回應碼 %d body %s", rec.Code, rec.Body.String())
	}
	f, err := q.GetFinding(ctx, "f1")
	if err != nil {
		t.Fatalf("查詢 finding 失敗: %v", err)
	}
	if f.Status != "resolved" {
		t.Errorf("狀態應為 resolved 實際為 %s", f.Status)
	}

	/* 重開回 open */
	rec = patchStatus(t, srv, "f1", `{"status": "open"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("重開回應碼 %d", rec.Code)
	}
	f, _ = q.GetFinding(ctx, "f1")
	if f.Status != "open" {
		t.Errorf("狀態應為 open 實際為 %s", f.Status)
	}
}

/* TestUpdateFindingStatusRejectsInvalid 不合法狀態應回 400 且不改變資料 */
func TestUpdateFindingStatusRejectsInvalid(t *testing.T) {
	ctx := context.Background()
	srv, q := newTestServer(t)

	p, _ := q.UpsertProjectByName(ctx, sqlc.UpsertProjectByNameParams{ID: "p1", Name: "demo"})
	seedScan(t, q, "scan1", p.ID, "/tmp/a")
	run, _ := q.CreateEngineRun(ctx, sqlc.CreateEngineRunParams{
		ID: "run1", ScanID: "scan1", Engine: "fake", Category: "SAST", Status: "completed",
	})
	seedFinding(t, q, "f1", p.ID, "scan1", run.ID, "HIGH")

	rec := patchStatus(t, srv, "f1", `{"status": "wontfix"}`)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("不合法狀態應回 400 實際 %d", rec.Code)
	}
	f, _ := q.GetFinding(ctx, "f1")
	if f.Status != "open" {
		t.Errorf("不合法請求不應改變狀態 實際為 %s", f.Status)
	}
}

/* TestUpdateFindingStatusNotFound 不存在的 finding 應回 404 */
func TestUpdateFindingStatusNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := patchStatus(t, srv, "nope", `{"status": "resolved"}`)
	if rec.Code != http.StatusNotFound {
		t.Errorf("不存在的 finding 應回 404 實際 %d", rec.Code)
	}
}

/* seedScanFinding 建立 scan 與 finding 的關聯 */
func seedScanFinding(t *testing.T, q *sqlc.Queries, scanID, findingID, hash string) {
	t.Helper()
	if err := q.CreateScanFinding(context.Background(), sqlc.CreateScanFindingParams{
		ScanID: scanID, FindingID: findingID, HashCode: hash,
	}); err != nil {
		t.Fatalf("建立測試 scan_finding 失敗: %v", err)
	}
}

/* TestScanDiff GET /api/scans/{id}/diff/{other} 回傳新增 消失 不變 */
func TestScanDiff(t *testing.T) {
	ctx := context.Background()
	srv, q := newTestServer(t)

	p, _ := q.UpsertProjectByName(ctx, sqlc.UpsertProjectByNameParams{ID: "p1", Name: "demo"})
	seedScan(t, q, "s1", p.ID, "/tmp/a")
	seedScan(t, q, "s2", p.ID, "/tmp/a")
	run, _ := q.CreateEngineRun(ctx, sqlc.CreateEngineRunParams{
		ID: "r1", ScanID: "s1", Engine: "fake", Category: "SAST", Status: "completed",
	})

	/* s1 觀察到 fa fb s2 觀察到 fa fc */
	seedFinding(t, q, "fa", p.ID, "s1", run.ID, "HIGH")
	seedFinding(t, q, "fb", p.ID, "s1", run.ID, "MEDIUM")
	seedFinding(t, q, "fc", p.ID, "s2", run.ID, "CRITICAL")
	seedScanFinding(t, q, "s1", "fa", "hash-fa")
	seedScanFinding(t, q, "s1", "fb", "hash-fb")
	seedScanFinding(t, q, "s2", "fa", "hash-fa")
	seedScanFinding(t, q, "s2", "fc", "hash-fc")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/scans/s1/diff/s2", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("diff 回應碼 %d body %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Added []struct {
			ID string `json:"id"`
		} `json:"added"`
		Removed []struct {
			ID string `json:"id"`
		} `json:"removed"`
		Unchanged int64 `json:"unchanged"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("解析 diff 回應失敗: %v", err)
	}
	if len(body.Added) != 1 || body.Added[0].ID != "fc" {
		t.Errorf("新增應只有 fc 實際 %+v", body.Added)
	}
	if len(body.Removed) != 1 || body.Removed[0].ID != "fb" {
		t.Errorf("消失應只有 fb 實際 %+v", body.Removed)
	}
	if body.Unchanged != 1 {
		t.Errorf("不變應為 1 實際 %d", body.Unchanged)
	}
}

/* TestScanDiffNotFound 不存在的 scan 應回 404 */
func TestScanDiffNotFound(t *testing.T) {
	srv, _ := newTestServer(t)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/scans/x/diff/y", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("不存在的 scan diff 應回 404 實際 %d", rec.Code)
	}
}

/* webFakeScanner 為 web 觸發測試用的假引擎 */
type webFakeScanner struct{}

func (f *webFakeScanner) Name() string                     { return "fake-web" }
func (f *webFakeScanner) Category() model.Category         { return model.CategorySAST }
func (f *webFakeScanner) Binary() string                   { return "fake-web" }
func (f *webFakeScanner) CheckInstalled() error            { return nil }
func (f *webFakeScanner) ExitCodeIsFindings(code int) bool { return code == 1 }
func (f *webFakeScanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	return "fake-web", nil
}
func (f *webFakeScanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	return &scanner.Result{RawOutput: []byte("{}")}, nil
}
func (f *webFakeScanner) Parse(raw []byte) ([]model.Finding, error) { return nil, nil }

/* TestStartScanRecordsWebTriggerSource 網頁觸發的掃描 trigger_source 應記為 web */
func TestStartScanRecordsWebTriggerSource(t *testing.T) {
	ctx := context.Background()
	srv, q := newTestServer(t)
	scanner.Register(&webFakeScanner{})

	body := strings.NewReader(`{"target": "/tmp/web-target", "engine": "fake-web"}`)
	req := httptest.NewRequest(http.MethodPost, "/api/scans", body)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("POST /api/scans 回應碼 %d body %s", rec.Code, rec.Body.String())
	}

	/* 掃描在背景 goroutine 執行 輪詢等待寫入 */
	deadline := time.Now().Add(3 * time.Second)
	for {
		scans, err := q.ListScans(ctx, sqlc.ListScansParams{Limit: 10, Offset: 0})
		if err == nil && len(scans) == 1 {
			if scans[0].TriggerSource != "web" {
				t.Errorf("trigger_source 應為 web 實際為 %s", scans[0].TriggerSource)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("等不到背景掃描寫入 scan 紀錄")
		}
		time.Sleep(20 * time.Millisecond)
	}
}
