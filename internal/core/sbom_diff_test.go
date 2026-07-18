package core

import (
	"context"
	"fmt"
	"testing"

	"github.com/cluion/vigila/internal/store/sqlc"
	"github.com/oklog/ulid/v2"
)

/* cdxWith 產一份含指定套件的極簡 CycloneDX JSON */
func cdxWith(pkgs ...[2]string) string {
	comps := ""
	for i, p := range pkgs {
		if i > 0 {
			comps += ","
		}
		comps += fmt.Sprintf(`{"type":"library","name":%q,"version":%q,"purl":"pkg:npm/%s@%s"}`, p[0], p[1], p[0], p[1])
	}
	return fmt.Sprintf(`{"components":[%s]}`, comps)
}

/* seedSBOMScan 在指定 project 下建一筆 scan 並存入一份 SBOM artifact 回傳 scan id */
func seedSBOMScan(t *testing.T, q *sqlc.Queries, projectID, content string) string {
	t.Helper()
	ctx := context.Background()
	scanID := ulid.Make().String()
	if _, err := q.CreateScan(ctx, sqlc.CreateScanParams{
		ID: scanID, ProjectID: projectID, Target: "/tmp/app",
		ScanType: "sbom", Status: "completed", TriggerSource: "cli",
	}); err != nil {
		t.Fatalf("建立 scan 失敗: %v", err)
	}
	if _, err := q.CreateArtifact(ctx, sqlc.CreateArtifactParams{
		ID: ulid.Make().String(), ScanID: scanID, Type: "sbom",
		Engine: "syft", Format: "cyclonedx-json", Content: content,
	}); err != nil {
		t.Fatalf("建立 artifact 失敗: %v", err)
	}
	return scanID
}

/* seedProject 建一個 project 回傳 id */
func seedProject(t *testing.T, q *sqlc.Queries, name string) string {
	t.Helper()
	id := ulid.Make().String()
	if _, err := q.UpsertProjectByName(context.Background(), sqlc.UpsertProjectByNameParams{ID: id, Name: name}); err != nil {
		t.Fatalf("建立 project 失敗: %v", err)
	}
	return id
}

func TestDiffSBOM(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)
	proj := seedProject(t, q, "app")

	from := seedSBOMScan(t, q, proj, cdxWith([2]string{"lodash", "4.17.20"}, [2]string{"left-pad", "1.3.0"}, [2]string{"express", "4.18.2"}))
	to := seedSBOMScan(t, q, proj, cdxWith([2]string{"lodash", "4.17.21"}, [2]string{"express", "4.18.2"}, [2]string{"axios", "1.6.0"}))

	res, err := DiffSBOM(ctx, q, from, to)
	if err != nil {
		t.Fatalf("DiffSBOM 失敗: %v", err)
	}

	if len(res.Diff.Added) != 1 || res.Diff.Added[0].Name != "axios" {
		t.Errorf("新增應只有 axios: %+v", res.Diff.Added)
	}
	if len(res.Diff.Removed) != 1 || res.Diff.Removed[0].Name != "left-pad" {
		t.Errorf("移除應只有 left-pad: %+v", res.Diff.Removed)
	}
	if len(res.Diff.Changed) != 1 || res.Diff.Changed[0].Name != "lodash" {
		t.Errorf("變動應只有 lodash: %+v", res.Diff.Changed)
	}
	if res.Diff.Unchanged != 1 {
		t.Errorf("不變應為 1 (express): %d", res.Diff.Unchanged)
	}
	if res.From.ID != from || res.To.ID != to {
		t.Errorf("From/To scan id 不符")
	}
	if res.FromTotal != 3 || res.ToTotal != 3 {
		t.Errorf("套件總數 From=%d To=%d 預期 3/3", res.FromTotal, res.ToTotal)
	}
}

/* TestDiffSBOMCrossProject 不同 project 的 SBOM 不可比較 */
func TestDiffSBOMCrossProject(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)

	from := seedSBOMScan(t, q, seedProject(t, q, "app-x"), cdxWith([2]string{"a", "1.0.0"}))
	to := seedSBOMScan(t, q, seedProject(t, q, "app-y"), cdxWith([2]string{"a", "1.0.0"}))

	if _, err := DiffSBOM(ctx, q, from, to); err == nil {
		t.Error("跨 project 的 SBOM diff 應回傳錯誤")
	}
}

/* TestDiffSBOMMissingArtifact scan 無 SBOM 時應回明確錯誤 */
func TestDiffSBOMMissingArtifact(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)
	proj := seedProject(t, q, "app")

	from := seedSBOMScan(t, q, proj, cdxWith([2]string{"a", "1.0.0"}))

	/* to 是一筆沒有 artifact 的 scan */
	toID := ulid.Make().String()
	if _, err := q.CreateScan(ctx, sqlc.CreateScanParams{
		ID: toID, ProjectID: proj, Target: "/tmp/app", ScanType: "single", Status: "completed", TriggerSource: "cli",
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := DiffSBOM(ctx, q, from, toID); err == nil {
		t.Error("缺 SBOM 的 scan 應回傳錯誤")
	}
}
