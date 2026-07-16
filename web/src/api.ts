/* Vigila API client 對應 Go 後端的 REST endpoints */

const BASE = "/api";

async function getJSON(path: string): Promise<any> {
  const res = await fetch(`${BASE}${path}`);
  if (!res.ok) {
    throw new Error(`API ${res.status}: ${await res.text()}`);
  }
  return res.json();
}

export interface Scan {
  id: string;
  project_id: string;
  project_name: string;
  target: string;
  scan_type: string;
  status: string;
  trigger_source: string;
  started_at: string | null;
  completed_at: string | null;
  created_at: string;
}

export interface EngineRun {
  id: string;
  scan_id: string;
  engine: string;
  category: string;
  command: string | null;
  status: string;
  exit_code: number | null;
  duration_ms: number | null;
  started_at: string | null;
  completed_at: string | null;
}

export interface ScanDetail extends Scan {
  engine_runs: EngineRun[];
}

export interface Finding {
  id: string;
  scan_id: string;
  engine_run_id: string;
  engine: string;
  category: string;
  rule_id: string;
  title: string;
  description: string | null;
  severity: string;
  cvss_score: number | null;
  cwe: string | null;
  file_path: string | null;
  start_line: number | null;
  end_line: number | null;
  snippet: string | null;
  pkg_name: string | null;
  installed_version: string | null;
  fixed_version: string | null;
  secret_type: string | null;
  unique_id_from_tool: string | null;
  status: string;
}

export interface ScanStat {
  scan: Scan;
  findings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
}

export interface Stats {
  recent_scans: ScanStat[];
}

export const api = {
  listScans: (): Promise<{ scans: Scan[] }> => getJSON("/scans"),
  getScan: (id: string): Promise<ScanDetail> => getJSON(`/scans/${id}`),
  listFindings: (scanId: string): Promise<{ findings: Finding[]; total: number }> =>
    getJSON(`/scans/${scanId}/findings`),
  stats: (): Promise<Stats> => getJSON("/stats"),
};
