import { useState, useEffect, useCallback } from "react";
import { api, type Scan, type ScanDetail, type Finding, type ScanStat } from "./api";

/* 輕量 hash router 處理 #/ 與 #/scans/{id} */
function useHashRoute(): [string, (path: string) => void] {
  const [route, setRoute] = useState(window.location.hash.slice(1) || "/");
  useEffect(() => {
    const onChange = () => setRoute(window.location.hash.slice(1) || "/");
    window.addEventListener("hashchange", onChange);
    return () => window.removeEventListener("hashchange", onChange);
  }, []);
  const navigate = useCallback((path: string) => {
    window.location.hash = path;
  }, []);
  return [route, navigate];
}

function formatTime(s: string | null): string {
  if (!s) return "—";
  return new Date(s).toLocaleString("zh-TW", { hour12: false });
}

function formatDuration(scan: ScanDetail | Scan): string {
  if (!scan.started_at || !scan.completed_at) return "—";
  const ms = new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime();
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function SeverityBadge({ severity }: { severity: string }) {
  return <span className={`badge badge-${severity}`}>{severity}</span>;
}

function StatusBadge({ status }: { status: string }) {
  return <span className={`status status-${status}`}>{status}</span>;
}

/* 掃描列表頁 */
function ScanList({ onOpen }: { onOpen: (id: string) => void }) {
  const [stats, setStats] = useState<ScanStat[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api.stats().then((s) => setStats(s.recent_scans)).catch((e) => setError(e.message));
  }, []);

  if (error) return <div className="error">{error}</div>;
  if (!stats) return <div className="loading">載入中</div>;
  if (stats.length === 0) {
    return <div className="loading">尚無掃描紀錄 用 <code>vigila scan &lt;path&gt;</code> 開始掃描</div>;
  }

  return (
    <div>
      <div className="stats-grid">
        <div className="stat-card">
          <div className="count" style={{ color: "var(--critical)" }}>
            {stats.reduce((a, s) => a + s.critical, 0)}
          </div>
          <div className="label">Critical</div>
        </div>
        <div className="stat-card">
          <div className="count" style={{ color: "var(--high)" }}>
            {stats.reduce((a, s) => a + s.high, 0)}
          </div>
          <div className="label">High</div>
        </div>
        <div className="stat-card">
          <div className="count" style={{ color: "var(--medium)" }}>
            {stats.reduce((a, s) => a + s.medium, 0)}
          </div>
          <div className="label">Medium</div>
        </div>
        <div className="stat-card">
          <div className="count" style={{ color: "var(--low)" }}>
            {stats.reduce((a, s) => a + s.low, 0)}
          </div>
          <div className="label">Low</div>
        </div>
      </div>

      <h2 style={{ marginBottom: "12px" }}>最近掃描</h2>
      {stats.map((s) => (
        <div key={s.scan.id} className="scan-card" onClick={() => onOpen(s.scan.id)}>
          <div className="scan-card-header">
            <div>
              <div className="scan-target">{s.scan.project_name}</div>
              <div className="scan-meta">
                {s.scan.target} · {formatTime(s.scan.created_at)} · {formatDuration(s.scan)}
              </div>
            </div>
            <StatusBadge status={s.scan.status} />
          </div>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
            <div className="badges">
              {s.critical > 0 && <SeverityBadge severity="CRITICAL" />}
              {s.high > 0 && <span className="badge badge-HIGH">{s.high}</span>}
              {s.medium > 0 && <span className="badge badge-MEDIUM">{s.medium}</span>}
              {s.low > 0 && <span className="badge badge-LOW">{s.low}</span>}
            </div>
            <span className="scan-meta">{s.findings} 個發現</span>
          </div>
        </div>
      ))}
    </div>
  );
}

/* 掃描詳情頁 含 findings 表格 */
function ScanDetailPage({ scanId, onBack }: { scanId: string; onBack: () => void }) {
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    Promise.all([api.getScan(scanId), api.listFindings(scanId)])
      .then(([s, f]) => {
        setScan(s);
        setFindings(f.findings);
      })
      .catch((e) => setError(e.message));
  }, [scanId]);

  if (error) return <div className="error">{error}</div>;
  if (!scan) return <div className="loading">載入中</div>;

  return (
    <div>
      <a className="back-link" href="#/" onClick={(e) => { e.preventDefault(); onBack(); }}>
        ← 返回列表
      </a>

      <div className="scan-card" style={{ cursor: "default" }}>
        <div className="scan-card-header">
          <div>
            <div className="scan-target">{scan.project_name}</div>
            <div className="scan-meta">
              {scan.target} · {formatTime(scan.created_at)} · {formatDuration(scan)}
            </div>
          </div>
          <StatusBadge status={scan.status} />
        </div>
        {scan.engine_runs.length > 0 && (
          <div style={{ marginTop: "8px" }}>
            {scan.engine_runs.map((r) => (
              <span key={r.id}>
                <span className="engine-badge">{r.engine}</span>
                <span className="scan-meta" style={{ marginRight: "12px" }}>
                  {r.status} · {r.duration_ms}ms
                </span>
              </span>
            ))}
          </div>
        )}
      </div>

      <h2 style={{ margin: "16px 0" }}>漏洞清單 共 {findings.length} 個</h2>

      {findings.length === 0 ? (
        <div className="loading">沒有發現</div>
      ) : (
        <table className="findings-table">
          <thead>
            <tr>
              <th>嚴重度</th>
              <th>漏洞</th>
              <th>引擎</th>
              <th>位置</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.id}>
                <td className="severity-cell">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td>
                  <div className="finding-title">{f.title}</div>
                  <div className="finding-rule">{f.rule_id}</div>
                  {f.fixed_version && (
                    <div className="scan-meta" style={{ marginTop: "4px", color: "#16a34a" }}>
                      修復版本 {f.fixed_version}
                    </div>
                  )}
                  {f.snippet && <div className="finding-snippet">{f.snippet}</div>}
                </td>
                <td>
                  <span className="engine-badge">{f.engine}</span>
                  <div className="scan-meta">{f.category}</div>
                </td>
                <td className="finding-location">
                  {f.file_path && <div>{f.file_path}</div>}
                  {f.start_line && <div>第 {f.start_line} 行</div>}
                  {f.pkg_name && (
                    <div>
                      {f.pkg_name} @ {f.installed_version}
                    </div>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

export default function App() {
  const [route, navigate] = useHashRoute();

  /* 解析 route #/scans/{id} */
  const scanMatch = route.match(/^\/scans\/(.+)$/);

  return (
    <div className="app">
      <div className="header">
        <h1>Vigila</h1>
        <span className="subtitle">資安掃描編排平台</span>
      </div>

      {scanMatch ? (
        <ScanDetailPage scanId={scanMatch[1]} onBack={() => navigate("/")} />
      ) : (
        <ScanList onOpen={(id) => navigate(`/scans/${id}`)} />
      )}
    </div>
  );
}
