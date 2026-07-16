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
