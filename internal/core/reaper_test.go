package core

import (
	"context"
	"testing"
	"time"

	"github.com/cluion/vigila/internal/store/sqlc"
)

/*
TestReapStaleRunningScans 逾時仍 running 的殘留掃描應被標為 failed
近期的 running 掃描不受影響 避免誤殺正在進行的掃描
*/
func TestReapStaleRunningScans(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)

	p, err := q.UpsertProjectByName(ctx, sqlc.UpsertProjectByNameParams{ID: "p1", Name: "demo"})
	if err != nil {
		t.Fatalf("建立 project 失敗: %v", err)
	}

	mkScan := func(id string, createdAt time.Time) {
		if _, err := q.CreateScan(ctx, sqlc.CreateScanParams{
			ID: id, ProjectID: p.ID, Target: "/tmp/a", ScanType: "single",
			Status: "running", TriggerSource: "cli",
		}); err != nil {
			t.Fatalf("建立 scan %s 失敗: %v", id, err)
		}
		if _, err := q.UpdateScanCreated(ctx, sqlc.UpdateScanCreatedParams{CreatedAt: createdAt, ID: id}); err != nil {
			t.Fatalf("回填 created_at 失敗: %v", err)
		}
	}

	/* stale 為 2 小時前 fresh 為現在 */
	mkScan("stale", time.Now().Add(-2*time.Hour).UTC())
	mkScan("fresh", time.Now().UTC())

	n, err := q.ReapStaleRunningScans(ctx)
	if err != nil {
		t.Fatalf("回收失敗: %v", err)
	}
	if n != 1 {
		t.Errorf("應回收 1 筆 實際 %d", n)
	}

	stale, _ := q.GetScan(ctx, "stale")
	if stale.Status != "failed" {
		t.Errorf("逾時掃描應標為 failed 實際 %s", stale.Status)
	}
	fresh, _ := q.GetScan(ctx, "fresh")
	if fresh.Status != "running" {
		t.Errorf("近期掃描應維持 running 實際 %s", fresh.Status)
	}
}
