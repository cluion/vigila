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
  profile: string | null;
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
  url: string | null;
  host: string | null;
  port: string | null;
  method: string | null;
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

export interface ScanDiff {
  from: Scan;
  to: Scan;
  added: Finding[];
  removed: Finding[];
  unchanged: number;
}

export interface Project {
  id: string;
  name: string;
  target: string | null;
  description: string | null;
  created_at: string;
  updated_at: string;
}

export interface TrendPoint {
  scan_id: string;
  created_at: string;
  added: number;
  resolved: number;
  total: number;
}

export interface Trends {
  points: TrendPoint[];
}

export interface Engine {
  name: string;
  category: string;
  target_kinds: string[];
  installed: boolean;
}

export const api = {
  listScans: (): Promise<{ scans: Scan[] }> => getJSON("/scans"),
  getScan: (id: string): Promise<ScanDetail> => getJSON(`/scans/${id}`),
  listFindings: (scanId: string): Promise<{ findings: Finding[]; total: number }> =>
    getJSON(`/scans/${scanId}/findings`),
  stats: (): Promise<Stats> => getJSON("/stats"),
  getScanDiff: (fromId: string, toId: string): Promise<ScanDiff> =>
    getJSON(`/scans/${fromId}/diff/${toId}`),
  listProjects: (): Promise<{ projects: Project[] }> => getJSON("/projects"),
  trends: (projectId: string): Promise<Trends> =>
    getJSON(`/projects/${projectId}/trends`),
  startScan: async (target: string, profile?: string): Promise<any> => {
    const res = await fetch(`${BASE}/scans`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, profile: profile || "", engine: profile ? "" : "all" }),
    });
    return res.json();
  },
  updateFindingStatus: async (id: string, status: string): Promise<Finding> => {
    const res = await fetch(`${BASE}/findings/${id}`, {
      method: "PATCH",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ status }),
    });
    if (!res.ok) {
      throw new Error(`API ${res.status}: ${await res.text()}`);
    }
    return res.json();
  },
  listProfiles: (): Promise<{ profiles: string }> => getJSON("/profiles"),
  listEngines: (): Promise<{ engines: Engine[] }> => getJSON("/engines"),
};

/* SSE 事件訂閱 回傳 cleanup 函數 */
export function subscribeEvents(onEvent: (type: string, data: any) => void): () => void {
  const es = new EventSource(`${BASE}/events`);
  const types = ["scan_started", "scan_completed", "engine_started", "engine_completed", "connected"];
  types.forEach((t) => {
    es.addEventListener(t, (e: MessageEvent) => {
      try {
        onEvent(t, JSON.parse(e.data));
      } catch {
        onEvent(t, {});
      }
    });
  });
  return () => es.close();
}
