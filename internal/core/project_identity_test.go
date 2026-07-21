package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cluion/vigila/internal/scanner"
)

/*
deriveProjectKey 對不同路徑的同名目錄應產生不同身分鍵 而顯示名相同
這是 A5a 修復的核心 舊模型以 basename 為身分鍵導致混淆
*/
func TestDeriveProjectKeyDistinguishesSameBasename(t *testing.T) {
	a := filepath.Join(t.TempDir(), "api")
	b := filepath.Join(t.TempDir(), "api")

	if deriveProjectName(a) != deriveProjectName(b) {
		t.Fatalf("顯示名應相同 皆為 basename api")
	}
	if deriveProjectKey(a) == deriveProjectKey(b) {
		t.Fatalf("不同路徑的同名目錄身分鍵不應相同 a=%s b=%s", deriveProjectKey(a), deriveProjectKey(b))
	}
}

/* deriveProjectKey 對 URL 取 scheme://host 對同站台不同 path 歸為同一鍵 */
func TestDeriveProjectKeyURL(t *testing.T) {
	if got := deriveProjectKey("https://example.com/a/b"); got != "https://example.com" {
		t.Errorf("URL 身分鍵應為 https://example.com 實際 %s", got)
	}
	if deriveProjectKey("https://example.com/a") != deriveProjectKey("https://example.com/b") {
		t.Error("同站台不同 path 應歸同一身分鍵")
	}
}

/* deriveProjectKey 對相對路徑與 . 應正規化為穩定的絕對路徑鍵 */
func TestDeriveProjectKeyNormalizesRelative(t *testing.T) {
	abs, _ := filepath.Abs(".")
	if got := deriveProjectKey("."); got != abs {
		t.Errorf("\".\" 應正規化為絕對路徑 %s 實際 %s", abs, got)
	}
}

/*
不同路徑的同名目錄經 RunSingle 後應為兩個獨立 project
直接驗證 A5a 混淆問題已修復
*/
func TestSameBasenameDifferentPathAreDistinctProjects(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)
	orch := New(q)

	dirA := filepath.Join(t.TempDir(), "api")
	dirB := filepath.Join(t.TempDir(), "api")
	if err := os.MkdirAll(dirA, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dirB, 0o755); err != nil {
		t.Fatal(err)
	}

	ra, err := orch.RunSingle(ctx, &fakeScanner{name: "fake"}, dirA, scanner.Options{})
	if err != nil {
		t.Fatalf("掃描 A 失敗: %v", err)
	}
	rb, err := orch.RunSingle(ctx, &fakeScanner{name: "fake"}, dirB, scanner.Options{})
	if err != nil {
		t.Fatalf("掃描 B 失敗: %v", err)
	}

	sa, _ := q.GetScan(ctx, ra.ScanID)
	sb, _ := q.GetScan(ctx, rb.ScanID)
	if sa.ProjectID == sb.ProjectID {
		t.Fatalf("不同路徑同名目錄不應共用 project 兩者皆 %s", sa.ProjectID)
	}
}

/* 同一目錄重複掃描應歸於同一 project（身分鍵相同 upsert 命中） */
func TestSameTargetRescanSharesProject(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)
	orch := New(q)

	dir := filepath.Join(t.TempDir(), "api")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	r1, err := orch.RunSingle(ctx, &fakeScanner{name: "fake"}, dir, scanner.Options{})
	if err != nil {
		t.Fatalf("首掃失敗: %v", err)
	}
	r2, err := orch.RunSingle(ctx, &fakeScanner{name: "fake"}, dir, scanner.Options{})
	if err != nil {
		t.Fatalf("重掃失敗: %v", err)
	}

	s1, _ := q.GetScan(ctx, r1.ScanID)
	s2, _ := q.GetScan(ctx, r2.ScanID)
	if s1.ProjectID != s2.ProjectID {
		t.Fatalf("同目錄重掃應共用 project s1=%s s2=%s", s1.ProjectID, s2.ProjectID)
	}
}

/*
WithProjectName override 情境（上傳）以檔名為身分鍵
即使 target 為不同暫存目錄 同一檔名仍歸於同一 project
*/
func TestProjectNameOverrideGroupsByName(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)

	r1, err := New(q).WithProjectName("app.zip").
		RunSingle(ctx, &fakeScanner{name: "fake"}, filepath.Join(t.TempDir(), "unpack1"), scanner.Options{})
	if err != nil {
		t.Fatalf("上傳掃描 1 失敗: %v", err)
	}
	r2, err := New(q).WithProjectName("app.zip").
		RunSingle(ctx, &fakeScanner{name: "fake"}, filepath.Join(t.TempDir(), "unpack2"), scanner.Options{})
	if err != nil {
		t.Fatalf("上傳掃描 2 失敗: %v", err)
	}

	s1, _ := q.GetScan(ctx, r1.ScanID)
	s2, _ := q.GetScan(ctx, r2.ScanID)
	if s1.ProjectID != s2.ProjectID {
		t.Fatalf("同檔名上傳應歸同一 project s1=%s s2=%s", s1.ProjectID, s2.ProjectID)
	}
}
