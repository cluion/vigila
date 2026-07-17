-- Vigila database schema (initial version)
--
-- Design principles:
--   Hierarchical: Project -> Scan -> EngineRun -> Finding
--   Event-sourced: Scan is immutable history; Finding is the deduped current view
--   Evidence chain: raw engine output kept in EngineRun.raw_output_path
--   Dual-key dedup: unique_id_from_tool + hash_code
--
-- Targets SQLite (local) and PostgreSQL (team); keep ANSI-compatible.

-- ============================================================================
-- Asset layer
-- ============================================================================
CREATE TABLE IF NOT EXISTS projects (
  id          TEXT PRIMARY KEY,
  name        TEXT NOT NULL UNIQUE,
  description TEXT,
  created_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at  TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

-- ============================================================================
-- Scan layer (immutable history, event-sourced)
-- ============================================================================
CREATE TABLE IF NOT EXISTS scans (
  id             TEXT PRIMARY KEY,
  project_id     TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  target         TEXT NOT NULL,
  scan_type      TEXT NOT NULL,      -- single | profile
  profile        TEXT,
  status         TEXT NOT NULL,      -- pending | running | completed | failed
  started_at     TIMESTAMP,
  completed_at   TIMESTAMP,
  trigger_source TEXT NOT NULL,      -- cli | web
  created_at     TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_id);
CREATE INDEX IF NOT EXISTS idx_scans_status  ON scans(status);

-- ============================================================================
-- Engine run layer (one scan may contain multiple engine runs)
-- ============================================================================
CREATE TABLE IF NOT EXISTS engine_runs (
  id              TEXT PRIMARY KEY,
  scan_id         TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  engine          TEXT NOT NULL,        -- semgrep | trivy | gitleaks
  category        TEXT NOT NULL,        -- SAST | SCA | SECRET | DAST | VA
  command         TEXT,                 -- actual command (evidence chain)
  status          TEXT NOT NULL,        -- running | completed | failed
  exit_code       INTEGER,
  duration_ms     INTEGER,
  raw_output_path TEXT,                 -- raw JSON evidence (kept for re-parse)
  error_message   TEXT,
  started_at      TIMESTAMP,
  completed_at    TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_engine_runs_scan ON engine_runs(scan_id);

-- ============================================================================
-- Finding layer (unified, cross-engine deduped current view)
-- ============================================================================
CREATE TABLE IF NOT EXISTS findings (
  id                  TEXT PRIMARY KEY,
  project_id          TEXT NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
  scan_id             TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  engine_run_id       TEXT NOT NULL REFERENCES engine_runs(id) ON DELETE CASCADE,

  -- source
  engine              TEXT NOT NULL,
  category            TEXT NOT NULL,

  -- identity
  rule_id             TEXT NOT NULL,
  title               TEXT NOT NULL,
  description         TEXT,

  -- severity (unified 5 levels)
  severity            TEXT NOT NULL,   -- UNKNOWN | LOW | MEDIUM | HIGH | CRITICAL
  cvss_score          REAL,
  cvss_vector         TEXT,
  cwe                 TEXT,

  -- location (for SAST / Secret)
  file_path           TEXT,
  start_line          INTEGER,
  end_line            INTEGER,
  start_col           INTEGER,
  end_col             INTEGER,
  snippet             TEXT,

  -- SCA specific
  pkg_name            TEXT,
  installed_version   TEXT,
  fixed_version       TEXT,

  -- Secret specific
  secret_type         TEXT,

  -- DAST / VA specific
  url                 TEXT,             -- 完整請求 URL
  host                TEXT,             -- 主機名或 IP
  port                TEXT,             -- 連接埠
  method              TEXT,             -- HTTP 方法

  -- references
  references_json     TEXT,             -- JSON array of URLs

  -- dedup dual keys
  unique_id_from_tool TEXT,
  hash_code           TEXT NOT NULL,

  -- status tracking
  status              TEXT NOT NULL DEFAULT 'open',  -- open | resolved | ignored
  created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_findings_hash     ON findings(hash_code);
CREATE INDEX IF NOT EXISTS idx_findings_project  ON findings(project_id);
CREATE INDEX IF NOT EXISTS idx_findings_scan     ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
-- core dedup: hash_code unique within a project
CREATE UNIQUE INDEX IF NOT EXISTS idx_findings_dedup ON findings(project_id, hash_code);

-- ============================================================================
-- Scan-finding association (event-sourced per-scan hash sets, enables diff)
-- ============================================================================
CREATE TABLE IF NOT EXISTS scan_findings (
  scan_id    TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  hash_code  TEXT NOT NULL,
  PRIMARY KEY (scan_id, hash_code)
);

CREATE INDEX IF NOT EXISTS idx_scan_findings_hash ON scan_findings(hash_code);
