package store

import "embed"

/* migrationsFS 嵌入 migrations 目錄 讓 binary 自帶 migration 無需外部檔案 */

//go:embed migrations/*.sql
var migrationsFS embed.FS
