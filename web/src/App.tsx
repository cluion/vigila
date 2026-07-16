import { useState, useEffect, useCallback, useMemo } from "react";
import { api, subscribeEvents, type Scan, type ScanDetail, type Finding, type ScanStat, type ScanDiff } from "./api";

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

const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

const FINDING_STATUSES = [
  { value: "open", label: "未處理" },
  { value: "resolved", label: "已解決" },
  { value: "ignored", label: "已忽略" },
];

function FindingStatusBadge({ status }: { status: string }) {
  const label = FINDING_STATUSES.find((s) => s.value === status)?.label || status;
  return <span className={`finding-status finding-status-${status}`}>{label}</span>;
}

/* 掃描列表頁 */
function ScanList({ onOpen }: { onOpen: (id: string) => void }) {
  const [stats, setStats] = useState<ScanStat[] | null>(null);
  const [error, setError] = useState("");
  const [scanProgress, setScanProgress] = useState<string>("");
  const [scanTarget, setScanTarget] = useState("");

  const refresh = () => {
    api.stats().then((s) => setStats(s.recent_scans)).catch((e) => setError(e.message));
  };

  useEffect(() => {
    refresh();
    /* 訂閱 SSE 掃描進度 完成後自動刷新 */
    const unsub = subscribeEvents((type, data) => {
      if (type === "scan_started") {
        setScanProgress(`掃描中 ${data.target} ...`);
      } else if (type === "engine_completed") {
        setScanProgress(`${data.engine} 完成 ${data.findings} 個發現`);
      } else if (type === "scan_completed") {
        setScanProgress("");
        refresh();
      }
    });
    return unsub;
  }, []);

  const triggerScan = async () => {
    if (!scanTarget.trim()) return;
    setScanProgress("啟動中 ...");
    await api.startScan(scanTarget.trim());
  };

  if (error) return <div className="error">{error}</div>;
  if (!stats) return <div className="loading">載入中</div>;

  return (
    <div>
      {/* 觸發掃描 */}
      <div className="trigger-bar">
        <input
          className="search-input"
          type="text"
          placeholder="掃描目標路徑 如 /tmp/myapp"
          value={scanTarget}
          onChange={(e) => setScanTarget(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && triggerScan()}
        />
        <button className="btn-primary" onClick={triggerScan} disabled={!!scanProgress}>
          掃描
        </button>
        {scanProgress && <span className="scan-progress">{scanProgress}</span>}
      </div>

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
                {s.scan.scan_type === "profile" && (
                  <span className="engine-badge" style={{ marginLeft: "6px" }}>profile</span>
                )}
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

/* diffFindingLocation 組出 finding 的位置描述 */
function diffFindingLocation(f: Finding): string {
  if (f.file_path) {
    return f.start_line ? `${f.file_path}:${f.start_line}` : f.file_path;
  }
  if (f.pkg_name) {
    return f.installed_version ? `${f.pkg_name}@${f.installed_version}` : f.pkg_name;
  }
  return "";
}

/* DiffFindingList 渲染 diff 的 findings 明細 */
function DiffFindingList({ findings }: { findings: Finding[] }) {
  return (
    <ul className="diff-list">
      {findings.map((f) => (
        <li key={f.id}>
          <SeverityBadge severity={f.severity} />
          <span className="engine-badge">{f.engine}</span>
          <span>{f.title}</span>
          <span className="finding-location">{diffFindingLocation(f)}</span>
        </li>
      ))}
    </ul>
  );
}

/* DiffSection 與同 project 的另一次掃描比較 新增/消失/不變 */
function DiffSection({ scan }: { scan: ScanDetail }) {
  const [others, setOthers] = useState<Scan[]>([]);
  const [compareTo, setCompareTo] = useState("");
  const [diff, setDiff] = useState<ScanDiff | null>(null);
  const [error, setError] = useState("");

  /* 抓同 project 的其他掃描 預設選時間上最近的前一次 */
  useEffect(() => {
    api
      .listScans()
      .then(({ scans }) => {
        const sameProject = scans.filter(
          (s) => s.project_id === scan.project_id && s.id !== scan.id
        );
        setOthers(sameProject);
        const prev = sameProject.find((s) => s.created_at < scan.created_at);
        setCompareTo(prev ? prev.id : "");
      })
      .catch((e) => setError(e.message));
  }, [scan.id, scan.project_id, scan.created_at]);

  useEffect(() => {
    if (!compareTo) {
      setDiff(null);
      return;
    }
    api
      .getScanDiff(compareTo, scan.id)
      .then(setDiff)
      .catch((e) => setError(e.message));
  }, [compareTo, scan.id]);

  if (others.length === 0) return null;

  return (
    <div className="diff-section">
      <div className="filter-bar" style={{ margin: 0 }}>
        <span className="scan-meta">與其他掃描比較</span>
        <select value={compareTo} onChange={(e) => setCompareTo(e.target.value)}>
          <option value="">選擇掃描</option>
          {others.map((s) => (
            <option key={s.id} value={s.id}>
              {formatTime(s.created_at)} · {s.id.slice(-8)}
            </option>
          ))}
        </select>
        {diff && (
          <span className="diff-summary">
            <span className="diff-count diff-count-added">新增 {diff.added.length}</span>
            <span className="diff-count diff-count-removed">消失 {diff.removed.length}</span>
            <span className="diff-count">不變 {diff.unchanged}</span>
          </span>
        )}
      </div>

      {error && <div className="error">{error}</div>}

      {diff && (diff.added.length > 0 || diff.removed.length > 0) && (
        <div className="diff-detail">
          {diff.added.length > 0 && (
            <div className="diff-block diff-block-added">
              <div className="diff-block-title">新增漏洞</div>
              <DiffFindingList findings={diff.added} />
            </div>
          )}
          {diff.removed.length > 0 && (
            <div className="diff-block diff-block-removed">
              <div className="diff-block-title">消失漏洞</div>
              <DiffFindingList findings={diff.removed} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/* 掃描詳情頁 含引擎卡 findings 篩選排序 */
function ScanDetailPage({ scanId, onBack }: { scanId: string; onBack: () => void }) {
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState("");

  /* 篩選狀態 */
  const [severityFilter, setSeverityFilter] = useState<string>("");
  const [engineFilter, setEngineFilter] = useState<string>("");
  const [statusFilter, setStatusFilter] = useState<string>("");
  const [search, setSearch] = useState("");
  const [sortBy, setSortBy] = useState<string>("severity");

  /* 標記漏洞狀態 成功後以不可變方式更新本地清單 */
  const updateStatus = async (id: string, status: string) => {
    try {
      const updated = await api.updateFindingStatus(id, status);
      setFindings((prev) => prev.map((f) => (f.id === id ? { ...f, status: updated.status } : f)));
    } catch (e) {
      setError((e as Error).message);
    }
  };

  useEffect(() => {
    Promise.all([api.getScan(scanId), api.listFindings(scanId)])
      .then(([s, f]) => {
        setScan(s);
        setFindings(f.findings);
      })
      .catch((e) => setError(e.message));
  }, [scanId]);

  /* 引擎列表 供篩選下拉 */
  const engines = useMemo(
    () => Array.from(new Set(findings.map((f) => f.engine))),
    [findings]
  );

  /* 篩選與排序後的 findings */
  const filtered = useMemo(() => {
    let out = [...findings];

    if (severityFilter) {
      out = out.filter((f) => f.severity === severityFilter);
    }
    if (engineFilter) {
      out = out.filter((f) => f.engine === engineFilter);
    }
    if (statusFilter) {
      out = out.filter((f) => f.status === statusFilter);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      out = out.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.rule_id.toLowerCase().includes(q) ||
          (f.file_path || "").toLowerCase().includes(q) ||
          (f.description || "").toLowerCase().includes(q)
      );
    }

    if (sortBy === "severity") {
      const rank: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
      out.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
    } else if (sortBy === "engine") {
      out.sort((a, b) => a.engine.localeCompare(b.engine));
    } else if (sortBy === "file") {
      out.sort((a, b) => (a.file_path || "").localeCompare(b.file_path || ""));
    }

    return out;
  }, [findings, severityFilter, engineFilter, statusFilter, search, sortBy]);

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
              {scan.profile && (
                <span className="engine-badge" style={{ marginLeft: "6px" }}>
                  {scan.profile}
                </span>
              )}
            </div>
          </div>
          <StatusBadge status={scan.status} />
        </div>

        {/* 引擎執行卡 */}
        {scan.engine_runs.length > 0 && (
          <div className="engine-runs">
            {scan.engine_runs.map((r) => (
              <div key={r.id} className={`engine-run status-bg-${r.status}`}>
                <span className="engine-badge">{r.engine}</span>
                <span className="scan-meta">{r.category}</span>
                <span className="scan-meta">· {r.status}</span>
                {r.duration_ms != null && <span className="scan-meta">· {r.duration_ms}ms</span>}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 與其他掃描比較 */}
      <DiffSection scan={scan} />

      {/* 篩選工具列 */}
      <div className="filter-bar">
        <input
          className="search-input"
          type="text"
          placeholder="搜尋漏洞 規則 檔案"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <select value={severityFilter} onChange={(e) => setSeverityFilter(e.target.value)}>
          <option value="">全部嚴重度</option>
          {SEVERITIES.map((s) => (
            <option key={s} value={s}>{s}</option>
          ))}
        </select>
        <select value={engineFilter} onChange={(e) => setEngineFilter(e.target.value)}>
          <option value="">全部引擎</option>
          {engines.map((e) => (
            <option key={e} value={e}>{e}</option>
          ))}
        </select>
        <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)}>
          <option value="">全部狀態</option>
          {FINDING_STATUSES.map((s) => (
            <option key={s.value} value={s.value}>{s.label}</option>
          ))}
        </select>
        <select value={sortBy} onChange={(e) => setSortBy(e.target.value)}>
          <option value="severity">依嚴重度排序</option>
          <option value="engine">依引擎排序</option>
          <option value="file">依檔案排序</option>
        </select>
        <span className="scan-meta" style={{ marginLeft: "auto" }}>
          {filtered.length} / {findings.length}
        </span>
      </div>

      <h2 style={{ margin: "16px 0" }}>漏洞清單</h2>

      {filtered.length === 0 ? (
        <div className="loading">{findings.length === 0 ? "沒有發現" : "沒有符合篩選條件的漏洞"}</div>
      ) : (
        <table className="findings-table">
          <thead>
            <tr>
              <th>嚴重度</th>
              <th>漏洞</th>
              <th>引擎</th>
              <th>位置</th>
              <th>狀態</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map((f) => (
              <tr key={f.id}>
                <td className="severity-cell">
                  <SeverityBadge severity={f.severity} />
                  {f.cvss_score != null && (
                    <div className="scan-meta" style={{ marginTop: "2px" }}>CVSS {f.cvss_score}</div>
                  )}
                </td>
                <td>
                  <div className="finding-title">{f.title}</div>
                  <div className="finding-rule">{f.rule_id}</div>
                  {f.cwe && <div className="scan-meta" style={{ marginTop: "2px" }}>{f.cwe}</div>}
                  {f.fixed_version && (
                    <div className="fix-version">修復版本 {f.fixed_version}</div>
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
                <td className="status-cell">
                  <FindingStatusBadge status={f.status} />
                  <div className="status-actions">
                    {f.status === "open" ? (
                      <>
                        <button className="btn-status" onClick={() => updateStatus(f.id, "resolved")}>
                          解決
                        </button>
                        <button className="btn-status" onClick={() => updateStatus(f.id, "ignored")}>
                          忽略
                        </button>
                      </>
                    ) : (
                      <button className="btn-status" onClick={() => updateStatus(f.id, "open")}>
                        重開
                      </button>
                    )}
                  </div>
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
