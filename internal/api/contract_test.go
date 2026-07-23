package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
	"github.com/cluion/vigila/internal/store/sqlc"
)

/* seedProject 建立 project 供 scan 的外鍵 供契約測試使用 */
func seedProject(t *testing.T, q *sqlc.Queries, id string) {
	t.Helper()
	if _, err := q.UpsertProject(context.Background(), sqlc.UpsertProjectParams{
		ID: id, Name: "demo", TargetKey: id,
	}); err != nil {
		t.Fatalf("建立測試 project 失敗: %v", err)
	}
}

/* seedRun 建立 engine_run 供 finding 的外鍵 供契約測試使用 */
func seedRun(t *testing.T, q *sqlc.Queries, id, scanID string) {
	t.Helper()
	if _, err := q.CreateEngineRun(context.Background(), sqlc.CreateEngineRunParams{
		ID: id, ScanID: scanID, Engine: "fake", Category: "SAST", Status: "completed",
	}); err != nil {
		t.Fatalf("建立測試 engine_run 失敗: %v", err)
	}
}

/* contractStub 為契約測試用最小引擎 供 /api/engines 有一筆可檢查的資料 */
type contractStub struct{}

func (contractStub) Name() string             { return "contract-stub" }
func (contractStub) Category() model.Category { return model.CategorySAST }
func (contractStub) Binary() string           { return "contract-stub" }
func (contractStub) VersionArgs() []string    { return nil }
func (contractStub) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetPath}
}
func (contractStub) InstallHint() scanner.InstallHint { return scanner.InstallHint{} }
func (contractStub) CheckInstalled() error            { return nil }
func (contractStub) BuildCommand(string, scanner.Options) (string, []string) {
	return "contract-stub", nil
}
func (contractStub) Run(context.Context, string, scanner.Options) (*scanner.Result, error) {
	return &scanner.Result{}, nil
}
func (contractStub) Parse([]byte) ([]model.Finding, error) { return nil, nil }
func (contractStub) ExitCodeIsFindings(int) bool           { return false }

/*
	API 契約測試 鎖定關鍵端點回應的核心 JSON 欄位

語意為向後相容檢查 新增欄位不會失敗（相容）移除或改名核心欄位會失敗（破壞）
守住對外 wire format 的穩定性 防意外破壞 API 消費端
*/

/* getJSONBody 打端點並把回應解為泛型結構 供欄位檢查 */
func getJSONBody(t *testing.T, srv *Server, path string) interface{} {
	t.Helper()
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s 狀態 = %d 預期 200 body=%s", path, rec.Code, rec.Body.String())
	}
	var v interface{}
	if err := json.Unmarshal(rec.Body.Bytes(), &v); err != nil {
		t.Fatalf("GET %s 回應非合法 JSON: %v", path, err)
	}
	return v
}

/* requireKeys 斷言 obj 為物件且含所有指定核心欄位 */
func requireKeys(t *testing.T, where string, obj interface{}, keys ...string) {
	t.Helper()
	m, ok := obj.(map[string]interface{})
	if !ok {
		t.Fatalf("%s 應為 JSON 物件 實際 %T", where, obj)
	}
	for _, k := range keys {
		if _, present := m[k]; !present {
			t.Errorf("%s 缺核心欄位 %q（破壞性變更）現有欄位 %v", where, k, keysOf(m))
		}
	}
}

/* keysOf 取 map 的鍵集合 供錯誤訊息 */
func keysOf(m map[string]interface{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

/* firstElem 取陣列首元素 空陣列失敗 */
func firstElem(t *testing.T, where string, v interface{}) interface{} {
	t.Helper()
	arr, ok := v.([]interface{})
	if !ok {
		t.Fatalf("%s 應為 JSON 陣列 實際 %T", where, v)
	}
	if len(arr) == 0 {
		t.Fatalf("%s 陣列為空 無法檢查元素契約", where)
	}
	return arr[0]
}

func TestContractScanEndpoints(t *testing.T) {
	srv, q := newTestServer(t)
	seedProject(t, q, "p1")
	seedScan(t, q, "s1", "p1", "/tmp/app")
	seedRun(t, q, "run1", "s1")
	seedFinding(t, q, "f1", "p1", "s1", "run1", "HIGH")

	scanKeys := []string{
		"id", "project_id", "target", "scan_type", "profile",
		"status", "trigger_source", "created_at", "project_name",
	}

	/* GET /api/scans 列表 envelope 含 scans/limit/offset */
	list := getJSONBody(t, srv, "/api/scans")
	requireKeys(t, "GET /api/scans", list, "scans", "limit", "offset")
	scans := list.(map[string]interface{})["scans"]
	requireKeys(t, "GET /api/scans .scans[0]", firstElem(t, "scans", scans), scanKeys...)

	/* GET /api/scans/{id} 詳情 含 engine_runs */
	detail := getJSONBody(t, srv, "/api/scans/s1")
	requireKeys(t, "GET /api/scans/{id}", detail, append(scanKeys, "engine_runs")...)
}

func TestContractFindingEndpoints(t *testing.T) {
	srv, q := newTestServer(t)
	seedProject(t, q, "p1")
	seedScan(t, q, "s1", "p1", "/tmp/app")
	seedRun(t, q, "run1", "s1")
	seedFinding(t, q, "f1", "p1", "s1", "run1", "HIGH")

	findingKeys := []string{
		"id", "project_id", "scan_id", "engine", "category",
		"rule_id", "title", "severity", "status", "hash_code",
	}

	/* GET /api/scans/{id}/findings 列表 envelope 含 findings/total */
	fs := getJSONBody(t, srv, "/api/scans/s1/findings")
	requireKeys(t, "GET .../findings", fs, "findings", "total")
	arr := fs.(map[string]interface{})["findings"]
	requireKeys(t, "GET .../findings .findings[0]", firstElem(t, "findings", arr), findingKeys...)

	/* GET /api/findings/{id} 單筆 */
	one := getJSONBody(t, srv, "/api/findings/f1")
	requireKeys(t, "GET /api/findings/{id}", one, findingKeys...)
}

func TestContractEnginesEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	scanner.Register(contractStub{})

	body := getJSONBody(t, srv, "/api/engines")
	m, ok := body.(map[string]interface{})
	if !ok {
		t.Fatalf("GET /api/engines 應為物件 實際 %T", body)
	}
	engines, ok := m["engines"]
	if !ok {
		t.Fatal("GET /api/engines 應含 engines 陣列")
	}
	requireKeys(t, "engine[0]", firstElem(t, "engines", engines),
		"name", "category", "target_kinds", "installed", "version",
		"source", "docker_capable", "docker_enabled", "installable",
		"pinned_version", "install_hint",
	)
}

func TestContractStatsEndpoint(t *testing.T) {
	srv, q := newTestServer(t)
	seedProject(t, q, "p1")
	seedScan(t, q, "s1", "p1", "/tmp/app")

	body := getJSONBody(t, srv, "/api/stats")
	requireKeys(t, "GET /api/stats", body, "recent_scans")
	m := body.(map[string]interface{})
	stat := firstElem(t, "recent_scans", m["recent_scans"])
	requireKeys(t, "recent_scans[0]", stat, "scan", "findings", "critical", "high", "medium", "low")
}

func TestContractProfilesEndpoint(t *testing.T) {
	srv, _ := newTestServer(t)
	requireKeys(t, "GET /api/profiles", getJSONBody(t, srv, "/api/profiles"), "profiles")
}
