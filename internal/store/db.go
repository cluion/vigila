/*
Package store 為資料庫層

CLI 與 Web 伺服器共用同一份 store 套件 寫入同一個資料庫
兩種部署模式
  - 本機模式 預設 SQLite 存於使用者資料目錄
  - 團隊模式 PostgreSQL

初始 schema 透過 migrations 套用
結構變更加新的 migration 檔
*/
package store

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	/* 純 Go SQLite driver 免 cgo 便於交叉編譯單一 binary */
	_ "modernc.org/sqlite"
)

// Config 描述如何開啟資料庫
type Config struct {
	Driver string // 目前支援 sqlite 預設 未來支援 postgres
	DSN    string // 資料庫連線字串 SQLite 為檔案路徑
}

/* Open 開啟資料庫並套用 migration 本機模式下 DSN 為空時使用預設路徑 */
func Open(ctx context.Context, cfg Config) (*sql.DB, error) {
	if cfg.Driver == "" {
		cfg.Driver = "sqlite"
	}

	if cfg.Driver != "sqlite" {
		return nil, fmt.Errorf("store: driver %q 尚未支援 目前僅 sqlite PostgreSQL 於團隊模式實作", cfg.Driver)
	}

	dsn := cfg.DSN
	if dsn == "" {
		var err error
		dsn, err = defaultSQLitePath()
		if err != nil {
			return nil, err
		}
	}

	/* modernc.org/sqlite 的 driver 名為 sqlite 連線參數 WAL 模式 並發讀寫友善 busy timeout 避免鎖失敗 外鍵強制啟用 */
	db, err := sql.Open("sqlite", dsn+"?_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)&_pragma=busy_timeout(5000)")
	if err != nil {
		return nil, fmt.Errorf("store: 開啟資料庫失敗: %w", err)
	}

	// SQLite 單連線寫入 設保守連線池
	db.SetMaxOpenConns(1)

	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: 無法連線資料庫: %w", err)
	}

	if err := migrate(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}

	return db, nil
}

/* defaultSQLitePath 回傳本機預設 SQLite 檔案路徑 並確保目錄存在 Linux 優先序 XDG_DATA_HOME 大於 HOME/.local/share */
func defaultSQLitePath() (string, error) {
	base := os.Getenv("XDG_DATA_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("store: 找不到使用者家目錄: %w", err)
		}
		base = filepath.Join(home, ".local", "share")
	}
	dir := filepath.Join(base, "vigila")
	/*
		0o750 不開放 world DB 內含掃描結果可能有密鑰
		#nosec G703 -- base 來自本人的 XDG_DATA_HOME 或家目錄 為本機自控路徑 非攻擊者輸入
	*/
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return "", fmt.Errorf("store: 建立資料目錄失敗: %w", err)
	}
	return filepath.Join(dir, "vigila.db"), nil
}

/* migrate 套用所有尚未執行的 migration 採 schema_migrations 版本表 逐檔執行 每個 migration 檔需具冪等性 用 CREATE TABLE IF NOT EXISTS 等 */
func migrate(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE IF NOT EXISTS schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
		);
	`); err != nil {
		return fmt.Errorf("store: 建立 migration 追蹤表失敗: %w", err)
	}

	embedded, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		return fmt.Errorf("store: 讀取 migrations 目錄失敗: %w", err)
	}

	for _, entry := range embedded {
		name := entry.Name()
		var version int
		if _, err := fmt.Sscanf(name, "%d_", &version); err != nil {
			continue // 忽略不符合命名的檔案
		}

		var applied int
		err := db.QueryRowContext(ctx, `SELECT version FROM schema_migrations WHERE version = ?`, version).Scan(&applied)
		if err == nil {
			continue // 已套用
		}
		if err != sql.ErrNoRows {
			return fmt.Errorf("store: 查詢 migration 版本失敗: %w", err)
		}

		stmt, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			return fmt.Errorf("store: 讀取 migration %s 失敗: %w", name, err)
		}

		if _, err := db.ExecContext(ctx, string(stmt)); err != nil {
			return fmt.Errorf("store: 套用 migration %s 失敗: %w", name, err)
		}

		if _, err := db.ExecContext(ctx, `INSERT INTO schema_migrations (version) VALUES (?)`, version); err != nil {
			return fmt.Errorf("store: 記錄 migration %s 失敗: %w", name, err)
		}
	}

	return nil
}
