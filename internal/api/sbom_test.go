package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cluion/vigila/internal/store/sqlc"
	"github.com/oklog/ulid/v2"
)

const testCycloneDX = `{
  "bomFormat": "CycloneDX",
  "components": [
    {"type": "library", "name": "django", "version": "2.0.0", "purl": "pkg:pypi/django@2.0.0"},
    {"type": "library", "name": "flask", "version": "0.12.2", "licenses": [{"license": {"id": "BSD-3-Clause"}}]}
  ]
}`

func TestGetScanSBOM(t *testing.T) {
	srv, q := newTestServer(t)
	ctx := context.Background()
	p, _ := q.UpsertProjectByName(ctx, sqlc.UpsertProjectByNameParams{ID: "p1", Name: "demo"})
	seedScan(t, q, "scan1", p.ID, "/tmp/a")

	if _, err := q.CreateArtifact(ctx, sqlc.CreateArtifactParams{
		ID:      ulid.Make().String(),
		ScanID:  "scan1",
		Type:    "sbom",
		Engine:  "syft",
		Format:  "cyclonedx-json",
		Content: testCycloneDX,
	}); err != nil {
		t.Fatalf("建立 SBOM artifact 失敗: %v", err)
	}

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/scans/scan1/sbom", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("回應碼 %d", rec.Code)
	}

	var body struct {
		Available bool `json:"available"`
		Total     int  `json:"total"`
		Packages  []struct {
			Name     string   `json:"name"`
			Version  string   `json:"version"`
			Licenses []string `json:"licenses"`
		} `json:"packages"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("解析回應失敗: %v", err)
	}
	if !body.Available {
		t.Error("有 SBOM 時 available 應為 true")
	}
	if body.Total != 2 || len(body.Packages) != 2 {
		t.Fatalf("套件數 = %d 預期 2", body.Total)
	}
	if body.Packages[0].Name != "django" || body.Packages[0].Version != "2.0.0" {
		t.Errorf("第一個套件 = %+v", body.Packages[0])
	}
	if len(body.Packages[1].Licenses) != 1 || body.Packages[1].Licenses[0] != "BSD-3-Clause" {
		t.Errorf("flask 授權 = %v", body.Packages[1].Licenses)
	}
}

/* seedSBOM 在既有 scan 上存一份 SBOM artifact */
func seedSBOM(t *testing.T, q *sqlc.Queries, scanID, content string) {
	t.Helper()
	if _, err := q.CreateArtifact(context.Background(), sqlc.CreateArtifactParams{
		ID: ulid.Make().String(), ScanID: scanID, Type: "sbom",
		Engine: "syft", Format: "cyclonedx-json", Content: content,
	}); err != nil {
		t.Fatalf("建立 SBOM artifact 失敗: %v", err)
	}
}

func TestGetScanSBOMDiff(t *testing.T) {
	srv, q := newTestServer(t)
	ctx := context.Background()
	p, _ := q.UpsertProjectByName(ctx, sqlc.UpsertProjectByNameParams{ID: "p1", Name: "demo"})
	seedScan(t, q, "old", p.ID, "/tmp/a")
	seedScan(t, q, "new", p.ID, "/tmp/a")
	seedSBOM(t, q, "old", `{"components":[{"type":"library","name":"django","version":"2.0.0","purl":"pkg:pypi/django@2.0.0"},{"type":"library","name":"flask","version":"0.12.2","purl":"pkg:pypi/flask@0.12.2"}]}`)
	seedSBOM(t, q, "new", `{"components":[{"type":"library","name":"django","version":"3.0.0","purl":"pkg:pypi/django@3.0.0"},{"type":"library","name":"requests","version":"2.31.0","purl":"pkg:pypi/requests@2.31.0"}]}`)

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/scans/new/sbom/diff/old", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("回應碼 %d", rec.Code)
	}

	var body struct {
		Added   []struct{ Name string } `json:"added"`
		Removed []struct{ Name string } `json:"removed"`
		Changed []struct {
			Name       string `json:"name"`
			OldVersion string `json:"old_version"`
			NewVersion string `json:"new_version"`
		} `json:"changed"`
		Unchanged int `json:"unchanged"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("解析回應失敗: %v", err)
	}
	if len(body.Added) != 1 || body.Added[0].Name != "requests" {
		t.Errorf("新增應只有 requests: %+v", body.Added)
	}
	if len(body.Removed) != 1 || body.Removed[0].Name != "flask" {
		t.Errorf("移除應只有 flask: %+v", body.Removed)
	}
	if len(body.Changed) != 1 || body.Changed[0].OldVersion != "2.0.0" || body.Changed[0].NewVersion != "3.0.0" {
		t.Errorf("django 應 2.0.0 → 3.0.0: %+v", body.Changed)
	}
	if body.Unchanged != 0 {
		t.Errorf("不變應為 0: %d", body.Unchanged)
	}
}

/* TestGetScanSBOMDiffMissing 缺 SBOM 時回 400 */
func TestGetScanSBOMDiffMissing(t *testing.T) {
	srv, q := newTestServer(t)
	ctx := context.Background()
	p, _ := q.UpsertProjectByName(ctx, sqlc.UpsertProjectByNameParams{ID: "p1", Name: "demo"})
	seedScan(t, q, "old", p.ID, "/tmp/a")
	seedScan(t, q, "new", p.ID, "/tmp/a")
	seedSBOM(t, q, "old", `{"components":[]}`)
	/* new 沒有 SBOM */

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/scans/new/sbom/diff/old", nil))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("缺 SBOM 應回 400 實際 %d", rec.Code)
	}
}

func TestGetScanSBOMNotAvailable(t *testing.T) {
	srv, q := newTestServer(t)
	ctx := context.Background()
	p, _ := q.UpsertProjectByName(ctx, sqlc.UpsertProjectByNameParams{ID: "p1", Name: "demo"})
	seedScan(t, q, "scan1", p.ID, "/tmp/a")

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/scans/scan1/sbom", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("無 SBOM 也應回 200 實際 %d", rec.Code)
	}

	var body struct {
		Available bool `json:"available"`
		Total     int  `json:"total"`
	}
	json.NewDecoder(rec.Body).Decode(&body)
	if body.Available {
		t.Error("無 SBOM 時 available 應為 false")
	}
	if body.Total != 0 {
		t.Errorf("無 SBOM 時 total 應為 0 實際 %d", body.Total)
	}
}
