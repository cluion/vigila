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

-- name: GetProjectByName :one
SELECT * FROM projects WHERE name = ?;

-- name: ListProjects :many
SELECT * FROM projects ORDER BY created_at DESC LIMIT ? OFFSET ?;

-- name: CreateProject :one
INSERT INTO projects (id, name, description) VALUES (?, ?, ?)
  ON CONFLICT(id) DO UPDATE SET name = excluded.name, updated_at = CURRENT_TIMESTAMP
  RETURNING *;

-- name: UpsertProjectByName :one
INSERT INTO projects (id, name, description) VALUES (?, ?, ?)
  ON CONFLICT(name) DO UPDATE SET updated_at = CURRENT_TIMESTAMP
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
  pkg_name, installed_version, fixed_version, secret_type, references_json,
  unique_id_from_tool, hash_code
) VALUES (
  ?, ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?, ?,
  ?, ?, ?, ?, ?,
  ?, ?
)
ON CONFLICT(project_id, hash_code) DO UPDATE SET
  scan_id = excluded.scan_id,
  engine_run_id = excluded.engine_run_id,
  severity = excluded.severity,
  status = CASE WHEN findings.status = 'resolved' THEN 'open' ELSE findings.status END
RETURNING *;

-- name: UpdateFindingStatus :one
UPDATE findings SET status = ? WHERE id = ? RETURNING *;

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
