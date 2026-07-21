-- projects 身分模型重建
--
-- 問題（A5a）舊模型以 name UNIQUE 為身分鍵 而 name 取自 target 的 basename
-- 導致不同路徑的同名目錄（如 ~/work/api 與 ~/side/api）被誤判為同一 project
-- 掃描歷史 趨勢 diff 全部混在一起
--
-- 修法 name 降為可重複的顯示標籤 新增 target_key 為正規化 target 的唯一身分鍵
-- 移除 name 的 UNIQUE 約束需重建表（SQLite 無 DROP CONSTRAINT）
--
-- FK 安全 scans 對 projects 有 ON DELETE CASCADE 若 FK 開啟時 DROP TABLE projects
-- 會隱式 DELETE 而連鎖刪光所有 scans/findings 故重建前關閉 FK
-- foreign_keys 設在交易外才生效（交易內為 no-op）設定會延續進後續交易
-- BEGIN/COMMIT 包裹確保任一步失敗即整體回滾 可安全重試
--
-- 回填 既有 project 的 target_key 暫以其 name 值填入（name 原為 UNIQUE 保證唯一）
-- 舊 project 身分維持不變 資料不遺失 往後新掃描以正規化路徑為鍵正確歸戶

PRAGMA foreign_keys=OFF;

BEGIN;

DROP TABLE IF EXISTS projects_rebuild;

CREATE TABLE projects_rebuild (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL,
  target_key  TEXT NOT NULL,
  description TEXT,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO projects_rebuild (id, name, target_key, description, created_at, updated_at)
  SELECT id, name, name, description, created_at, updated_at FROM projects;

DROP TABLE projects;

ALTER TABLE projects_rebuild RENAME TO projects;

CREATE UNIQUE INDEX IF NOT EXISTS idx_projects_target_key ON projects(target_key);

COMMIT;

PRAGMA foreign_keys=ON;
