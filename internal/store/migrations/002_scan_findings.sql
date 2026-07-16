-- scan_findings: per-scan finding association (event-sourced)
--
-- findings is a deduped current view; re-scans move finding.scan_id to the
-- latest scan, so historical per-scan sets cannot be reconstructed from it.
-- This table records the exact hash set each scan observed, enabling scan diff.

CREATE TABLE IF NOT EXISTS scan_findings (
  scan_id    TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  finding_id TEXT NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
  hash_code  TEXT NOT NULL,
  PRIMARY KEY (scan_id, hash_code)
);

CREATE INDEX IF NOT EXISTS idx_scan_findings_hash ON scan_findings(hash_code);

-- Backfill: existing findings only retain their latest scan association.
INSERT OR IGNORE INTO scan_findings (scan_id, finding_id, hash_code)
SELECT scan_id, id, hash_code FROM findings;
