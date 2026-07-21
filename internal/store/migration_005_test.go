package store

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
)

/* applyMigrationVersion 從嵌入的 migrations 讀出指定版本的檔案並執行 供測試逐版重放 */
func applyMigrationVersion(t *testing.T, ctx context.Context, db *sql.DB, version int) {
	t.Helper()
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("讀 migrations 目錄失敗: %v", err)
	}
	for _, e := range entries {
		var v int
		if _, err := fmt.Sscanf(e.Name(), "%d_", &v); err != nil || v != version {
			continue
		}
		stmt, err := migrationsFS.ReadFile("migrations/" + e.Name())
		if err != nil {
			t.Fatalf("讀 migration %s 失敗: %v", e.Name(), err)
		}
		if _, err := db.ExecContext(ctx, string(stmt)); err != nil {
			t.Fatalf("套用 migration %s 失敗: %v", e.Name(), err)
		}
		return
	}
	t.Fatalf("找不到 migration 版本 %d", version)
}

/*
TestMigration005PreservesLegacyData 驗證 projects 身分模型重建（005）在既有資料上安全升級
先套 001-004 建立舊 schema 與資料 再套 005
斷言 scans 未被 FK 連鎖刪除 target_key 由 name 回填 且升級後可插入同名不同鍵 project
*/
func TestMigration005PreservesLegacyData(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "legacy.db")

	// 與 Open 相同的連線參數 外鍵強制開啟（重現連鎖刪除風險情境）
	db, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatalf("開啟 DB 失敗: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	// 套用 005 之前的所有 migration 得到舊 schema（projects.name UNIQUE 無 target_key）
	for _, v := range []int{1, 2, 3, 4} {
		applyMigrationVersion(t, ctx, db, v)
	}

	// 塞入舊資料：一個 project + 一個 scan（scans 對 projects 有 ON DELETE CASCADE）
	if _, err := db.ExecContext(ctx, `INSERT INTO projects (id, name) VALUES ('p1', 'api')`); err != nil {
		t.Fatalf("插入舊 project 失敗: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO scans (id, project_id, target, scan_type, status, trigger_source) VALUES ('s1', 'p1', '/work/api', 'single', 'completed', 'cli')`); err != nil {
		t.Fatalf("插入舊 scan 失敗: %v", err)
	}

	// 套用 005 身分模型重建
	applyMigrationVersion(t, ctx, db, 5)

	// scan 必須存活（未被連鎖刪除）
	var scanCount int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM scans`).Scan(&scanCount); err != nil {
		t.Fatalf("查 scans 失敗: %v", err)
	}
	if scanCount != 1 {
		t.Fatalf("scans 遭連鎖刪除 count=%d 期望 1", scanCount)
	}

	// target_key 應由 name 回填
	var targetKey string
	if err := db.QueryRowContext(ctx, `SELECT target_key FROM projects WHERE id = 'p1'`).Scan(&targetKey); err != nil {
		t.Fatalf("查 target_key 失敗: %v", err)
	}
	if targetKey != "api" {
		t.Fatalf("target_key 應回填為 name 值 api 實際 %q", targetKey)
	}

	// 升級後 name 不再唯一 同名不同 target_key 應可並存
	if _, err := db.ExecContext(ctx, `INSERT INTO projects (id, name, target_key) VALUES ('p2', 'api', '/side/api')`); err != nil {
		t.Fatalf("升級後同名不同路徑 project 應可插入 但失敗: %v", err)
	}

	// target_key 唯一性應生效
	if _, err := db.ExecContext(ctx, `INSERT INTO projects (id, name, target_key) VALUES ('p3', 'x', 'api')`); err == nil {
		t.Fatal("重複 target_key 應違反唯一索引 但成功插入")
	}

	// FK 完整性檢查應無違規（重建後 scans.project_id 仍正確指向 projects）
	rows, err := db.QueryContext(ctx, `PRAGMA foreign_key_check`)
	if err != nil {
		t.Fatalf("foreign_key_check 失敗: %v", err)
	}
	defer rows.Close()
	if rows.Next() {
		t.Fatal("重建後存在外鍵完整性違規")
	}
}
