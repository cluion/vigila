package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cluion/vigila/internal/store"
	"github.com/cluion/vigila/internal/store/sqlc"
)

const cliCycloneDX = `{"bomFormat":"CycloneDX","components":[` +
	`{"type":"library","name":"django","version":"2.0.0"},` +
	`{"type":"library","name":"flask","version":"0.12.2"}]}`

/* newSBOMTestDB 開一個含 project scan 與 SBOM artifact 的暫存 DB */
func newSBOMTestDB(t *testing.T, scanID string) *sqlc.Queries {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "t.db")})
	if err != nil {
		t.Fatalf("開啟測試 DB 失敗: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	q := sqlc.New(db)

	p, err := q.UpsertProjectByName(ctx, sqlc.UpsertProjectByNameParams{ID: "p1", Name: "demo"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := q.CreateScan(ctx, sqlc.CreateScanParams{
		ID: scanID, ProjectID: p.ID, Target: "/tmp/a", ScanType: "single", Status: "completed", TriggerSource: "cli",
	}); err != nil {
		t.Fatal(err)
	}
	return q
}

func TestExportSBOMToStdout(t *testing.T) {
	ctx := context.Background()
	q := newSBOMTestDB(t, "scan1")
	if _, err := q.CreateArtifact(ctx, sqlc.CreateArtifactParams{
		ID: "a1", ScanID: "scan1", Type: "sbom", Engine: "syft", Format: "cyclonedx-json", Content: cliCycloneDX,
	}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	if err := exportSBOM(ctx, q, "scan1", "", &out); err != nil {
		t.Fatalf("匯出失敗: %v", err)
	}
	if out.String() != cliCycloneDX {
		t.Errorf("stdout 應為原始 SBOM 內容 實際 %q", out.String())
	}
}

func TestExportSBOMToFile(t *testing.T) {
	ctx := context.Background()
	q := newSBOMTestDB(t, "scan1")
	if _, err := q.CreateArtifact(ctx, sqlc.CreateArtifactParams{
		ID: "a1", ScanID: "scan1", Type: "sbom", Engine: "syft", Format: "cyclonedx-json", Content: cliCycloneDX,
	}); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "sbom.json")
	var out bytes.Buffer
	if err := exportSBOM(ctx, q, "scan1", path, &out); err != nil {
		t.Fatalf("匯出失敗: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("讀取匯出檔失敗: %v", err)
	}
	if string(got) != cliCycloneDX {
		t.Errorf("檔案內容與 SBOM 不符")
	}
	/* 確認狀態訊息含檔名與套件數 */
	msg := out.String()
	if !strings.Contains(msg, path) || !strings.Contains(msg, "2 個套件") {
		t.Errorf("匯出訊息 = %q 應含檔名與套件數", msg)
	}
}

func TestExportSBOMMissing(t *testing.T) {
	ctx := context.Background()
	q := newSBOMTestDB(t, "scan1") // 未建立 artifact
	var out bytes.Buffer
	err := exportSBOM(ctx, q, "scan1", "", &out)
	if err == nil {
		t.Fatal("無 SBOM 應回錯")
	}
	if !strings.Contains(err.Error(), "--sbom") {
		t.Errorf("錯誤訊息應引導使用 --sbom 實際 %q", err.Error())
	}
}
