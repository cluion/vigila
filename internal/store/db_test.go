package store

import (
	"context"
	"path/filepath"
	"testing"
)

/* TestOpenCreatesDatabase 確認 Open 建立資料庫並套用 migration 且核心資料表存在 */
func TestOpenCreatesDatabase(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")

	db, err := Open(ctx, Config{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		t.Fatalf("Open 失敗: %v", err)
	}
	defer db.Close()

	// 驗證所有核心資料表存在
	tables := []string{"projects", "scans", "engine_runs", "findings", "schema_migrations"}
	for _, table := range tables {
		var name string
		err := db.QueryRowContext(ctx,
			`SELECT name FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&name)
		if err != nil {
			t.Errorf("資料表 %s 不存在或查詢失敗: %v", table, err)
		}
	}
}

/* TestMigrationIsIdempotent 確認重複呼叫 Open 不會出錯 */
func TestMigrationIsIdempotent(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")

	// 第一次開啟 套用 migration
	db1, err := Open(ctx, Config{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		t.Fatalf("第一次 Open 失敗: %v", err)
	}
	db1.Close()

	// 第二次開啟 migration 應已標記為套用 不重跑
	db2, err := Open(ctx, Config{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		t.Fatalf("第二次 Open 失敗 migration 應冪等: %v", err)
	}
	defer db2.Close()

	// 確認 migration 版本確實有記錄
	var count int
	if err := db2.QueryRowContext(ctx, `SELECT COUNT(*) FROM schema_migrations`).Scan(&count); err != nil {
		t.Fatalf("查詢 schema_migrations 失敗: %v", err)
	}
	if count == 0 {
		t.Error("schema_migrations 為空 migration 未被記錄")
	}
}

/* TestFindingsDedupIndex 確認 findings 的去重唯一索引存在 這是整個去重機制的資料庫層基礎 */
func TestFindingsDedupIndex(t *testing.T) {
	ctx := context.Background()
	dbPath := filepath.Join(t.TempDir(), "test.db")

	db, err := Open(ctx, Config{Driver: "sqlite", DSN: dbPath})
	if err != nil {
		t.Fatalf("Open 失敗: %v", err)
	}
	defer db.Close()

	var name string
	err = db.QueryRowContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='index' AND name='idx_findings_dedup'`).Scan(&name)
	if err != nil {
		t.Fatalf("去重索引 idx_findings_dedup 不存在: %v", err)
	}
}

/* TestOpenUnsupportedDriver 非 sqlite driver 應回錯 */
func TestOpenUnsupportedDriver(t *testing.T) {
	if _, err := Open(context.Background(), Config{Driver: "postgres"}); err == nil {
		t.Error("postgres driver 應回不支援錯誤")
	}
}

/* TestOpenDefaultPath DSN 為空時走 defaultSQLitePath 以 XDG_DATA_HOME 導向暫存目錄 */
func TestOpenDefaultPath(t *testing.T) {
	t.Setenv("XDG_DATA_HOME", t.TempDir())
	db, err := Open(context.Background(), Config{}) // Driver 空 → 預設 sqlite DSN 空 → 預設路徑
	if err != nil {
		t.Fatalf("預設路徑開啟失敗: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	if err := db.Ping(); err != nil {
		t.Errorf("預設路徑資料庫應可 ping: %v", err)
	}
}

/* TestDefaultSQLitePath 直接驗證預設路徑組法與目錄建立 */
func TestDefaultSQLitePath(t *testing.T) {
	base := t.TempDir()
	t.Setenv("XDG_DATA_HOME", base)
	p, err := defaultSQLitePath()
	if err != nil {
		t.Fatalf("defaultSQLitePath 失敗: %v", err)
	}
	if filepath.Dir(p) != filepath.Join(base, "vigila") {
		t.Errorf("路徑應在 %s/vigila 下 實際 %s", base, p)
	}
}
