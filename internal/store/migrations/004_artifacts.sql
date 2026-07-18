-- Scan artifact 層
--
-- artifact 與 finding 分開 finding 是漏洞 artifact 是掃描產出的其他物件
-- 首個用途為 SBOM 軟體物料清單 syft 產 CycloneDX JSON 掛在 scan 底下

CREATE TABLE IF NOT EXISTS artifacts (
  id         TEXT PRIMARY KEY,
  scan_id    TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  type       TEXT NOT NULL,   -- sbom
  engine     TEXT NOT NULL,   -- syft
  format     TEXT NOT NULL,   -- cyclonedx-json
  content    TEXT NOT NULL,   -- 原始 artifact 內容 SBOM JSON
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_artifacts_scan ON artifacts(scan_id);
