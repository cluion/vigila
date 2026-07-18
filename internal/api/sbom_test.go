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
