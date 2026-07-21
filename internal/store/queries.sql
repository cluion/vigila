-- Vigila SQL queries (consumed by sqlc to generate type-safe Go code).
--
-- Naming convention (sqlc):
--   :one   returns a single row
--   :many  returns multiple rows
--   :exec  no data returned
--
-- Targets SQLite; keep ANSI-compatible for future PostgreSQL support.

-- ============================================================================
-- projects
-- ============================================================================

-- name: GetProject :one
SELECT * FROM projects WHERE id = ?;

-- name: GetProjectByTargetKey :one
SELECT * FROM projects WHERE target_key = ?;

-- name: ListProjects :many
SELECT * FROM projects ORDER BY created_at DESC LIMIT ? OFFSET ?;

-- Upsert keyed by target_key (identity); name is a mutable display label.
-- Re-scanning the same target maps to the same project row.
-- name: UpsertProject :one
INSERT INTO projects (id, name, target_key, description) VALUES (?, ?, ?, ?)
  ON CONFLICT(target_key) DO UPDATE SET name = excluded.name, updated_at = CURRENT_TIMESTAMP
  RETURNING *;

-- ============================================================================
-- scans
-- ============================================================================

-- name: GetScan :one
SELECT * FROM scans WHERE id = ?;

-- name: ListScans :many
SELECT * FROM scans ORDER BY created_at DESC LIMIT ? OFFSET ?;

-- name: ListScansByProject :many
SELECT * FROM scans WHERE project_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?;

-- name: ListProjectScansChronological :many
SELECT * FROM scans WHERE project_id = ? ORDER BY created_at ASC;

-- name: CreateScan :one
INSERT INTO scans (id, project_id, target, scan_type, profile, status, trigger_source)
VALUES (?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateScanStatus :one
UPDATE scans
  SET status = ?,
      started_at = COALESCE(?, started_at),
      completed_at = COALESCE(?, completed_at)
WHERE id = ?
RETURNING *;

-- name: UpdateScanCreated :one
UPDATE scans SET created_at = ? WHERE id = ? RETURNING *;

-- name: DeleteScan :exec
DELETE FROM scans WHERE id = ?;

-- name: ReapStaleRunningScans :execrows
-- mark scans left in 'running' by a dead process (killed / Ctrl-C) as failed.
-- datetime('now', ...) yields the same text format as CURRENT_TIMESTAMP (SQLite).
UPDATE scans
  SET status = 'failed', completed_at = CURRENT_TIMESTAMP
WHERE status = 'running' AND created_at < datetime('now', '-1 hour');

-- ============================================================================
-- engine_runs
-- ============================================================================

-- name: GetEngineRun :one
SELECT * FROM engine_runs WHERE id = ?;

-- name: ListEngineRunsByScan :many
SELECT * FROM engine_runs WHERE scan_id = ? ORDER BY started_at ASC;

-- name: CreateEngineRun :one
INSERT INTO engine_runs (
  id, scan_id, engine, category, command, status, exit_code, duration_ms,
  raw_output_path, error_message, started_at, completed_at
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: UpdateEngineRunStatus :one
UPDATE engine_runs
  SET status = ?,
      exit_code = ?,
      duration_ms = ?,
      error_message = ?,
      completed_at = ?
WHERE id = ?
RETURNING *;

-- ============================================================================
-- findings
-- ============================================================================

-- name: GetFinding :one
SELECT * FROM findings WHERE id = ?;

-- name: ListFindingsByScan :many
SELECT * FROM findings WHERE scan_id = ?
ORDER BY
  CASE severity
    WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2
    WHEN 'LOW' THEN 1 ELSE 0
  END DESC;

-- name: ListFindingsByProject :many
SELECT * FROM findings WHERE project_id = ?
ORDER BY
  CASE severity
    WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2
    WHEN 'LOW' THEN 1 ELSE 0
  END DESC
LIMIT ? OFFSET ?;

-- name: UpsertFinding :one
INSERT INTO findings (
  id, project_id, scan_id, engine_run_id, engine, category,
  rule_id, title, description, severity, cvss_score, cvss_vector, cwe,
  file_path, start_line, end_line, start_col, end_col, snippet,
  pkg_name, installed_version, fixed_version, secret_type,
  url, host, port, method,
  references_json,
  unique_id_from_tool, hash_code
) VALUES (
  ?, ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?, ?,
  ?, ?, ?, ?,
  ?, ?, ?, ?,
  ?,
  ?, ?
)
ON CONFLICT(project_id, hash_code) DO UPDATE SET
  scan_id = excluded.scan_id,
  engine_run_id = excluded.engine_run_id,
  severity = excluded.severity,
  -- refresh descriptive fields from the latest scan; keep old value when the new one is NULL
  title = excluded.title,
  description = COALESCE(excluded.description, findings.description),
  cvss_score = COALESCE(excluded.cvss_score, findings.cvss_score),
  cvss_vector = COALESCE(excluded.cvss_vector, findings.cvss_vector),
  cwe = COALESCE(excluded.cwe, findings.cwe),
  fixed_version = COALESCE(excluded.fixed_version, findings.fixed_version),
  snippet = COALESCE(excluded.snippet, findings.snippet),
  references_json = COALESCE(excluded.references_json, findings.references_json),
  status = CASE WHEN findings.status = 'resolved' THEN 'open' ELSE findings.status END
RETURNING *;

-- name: UpdateFindingStatus :one
UPDATE findings SET status = ? WHERE id = ? RETURNING *;

-- ============================================================================
-- scan_findings (per-scan association, diff)
-- ============================================================================

-- name: CreateScanFinding :exec
INSERT INTO scan_findings (scan_id, finding_id, hash_code) VALUES (?, ?, ?)
ON CONFLICT(scan_id, hash_code) DO NOTHING;

-- name: ListFindingsOnlyInScan :many
-- findings observed by scan ?1 but not by scan ?2, joined to current detail
SELECT f.* FROM scan_findings sf
JOIN findings f ON f.id = sf.finding_id
WHERE sf.scan_id = ?1 AND sf.hash_code NOT IN (
  SELECT other.hash_code FROM scan_findings other WHERE other.scan_id = ?2
)
ORDER BY
  CASE f.severity
    WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2
    WHEN 'LOW' THEN 1 ELSE 0
  END DESC;

-- name: ListFindingsByScanAssoc :many
-- findings actually observed by a scan, reconstructed via scan_findings.
-- findings.scan_id migrates on later upserts, so a plain WHERE scan_id is wrong.
SELECT f.* FROM scan_findings sf
JOIN findings f ON f.id = sf.finding_id
WHERE sf.scan_id = ?
ORDER BY
  CASE f.severity
    WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 WHEN 'MEDIUM' THEN 2
    WHEN 'LOW' THEN 1 ELSE 0
  END DESC;

-- name: CountFindingsByScanAssoc :one
SELECT COUNT(*) FROM scan_findings WHERE scan_id = ?;

-- name: CountFindingsBySeverityByScanAssoc :many
SELECT f.severity, COUNT(*) AS count
FROM scan_findings sf
JOIN findings f ON f.id = sf.finding_id
WHERE sf.scan_id = ?
GROUP BY f.severity;

-- name: CountCommonFindings :one
SELECT COUNT(*) FROM scan_findings a
JOIN scan_findings b ON a.hash_code = b.hash_code
WHERE a.scan_id = ?1 AND b.scan_id = ?2;

-- name: CountFindingsOnlyInScan :one
SELECT COUNT(*) FROM scan_findings sf
WHERE sf.scan_id = ?1 AND NOT EXISTS (
  SELECT 1 FROM scan_findings other WHERE other.scan_id = ?2 AND other.hash_code = sf.hash_code
);

-- ============================================================================
-- stats
-- ============================================================================

-- name: CountFindingsByProject :one
SELECT COUNT(*) FROM findings WHERE project_id = ?;

-- name: CountFindingsBySeverity :many
SELECT severity, COUNT(*) AS count
FROM findings
WHERE project_id = ?
GROUP BY severity;

-- name: CountFindingsByScan :one
SELECT COUNT(*) FROM findings WHERE scan_id = ?;

-- name: CountFindingsBySeverityByScan :many
SELECT severity, COUNT(*) AS count
FROM findings
WHERE scan_id = ?
GROUP BY severity;

-- name: CreateArtifact :one
INSERT INTO artifacts (id, scan_id, type, engine, format, content)
VALUES (?, ?, ?, ?, ?, ?)
RETURNING *;

-- name: GetLatestSBOMByScan :one
SELECT * FROM artifacts
WHERE scan_id = ? AND type = 'sbom'
ORDER BY created_at DESC
LIMIT 1;
