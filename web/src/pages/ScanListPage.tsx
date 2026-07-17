import { useState, useEffect } from "react";
import { api, subscribeEvents, type ScanStat } from "@/lib/api";
import { formatTime, formatDuration } from "@/lib/constants";
import { SeverityBadge, StatusBadge, EngineBadge } from "@/components/badges";
import { TrendChart } from "@/components/TrendChart";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

/* 掃描列表頁 儀表板 */
export function ScanListPage({ onOpen }: { onOpen: (id: string) => void }) {
  const [stats, setStats] = useState<ScanStat[] | null>(null);
  const [error, setError] = useState("");
  const [scanProgress, setScanProgress] = useState<string>("");
  const [scanTarget, setScanTarget] = useState("");

  const refresh = () => {
    api
      .stats()
      .then((s) => setStats(s.recent_scans))
      .catch((e) => setError((e as Error).message));
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

  if (error)
    return (
      <div className="rounded-lg border border-critical/30 bg-critical/10 p-4 text-sm text-critical">
        {error}
      </div>
    );
  if (!stats) return <div className="py-12 text-center text-sm text-muted-foreground">載入中</div>;

  const sum = (key: "critical" | "high" | "medium" | "low") =>
    stats.reduce((a, s) => a + s[key], 0);

  return (
    <div>
      {/* 觸發掃描 */}
      <div className="mb-5 flex flex-wrap items-center gap-2">
        <Input
          type="text"
          className="min-w-[200px] flex-1"
          placeholder="掃描目標 路徑 URL 或 host 如 /tmp/myapp http://host 192.168.1.10"
          value={scanTarget}
          onChange={(e) => setScanTarget(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && triggerScan()}
        />
        <Button onClick={triggerScan} disabled={!!scanProgress}>
          掃描
        </Button>
        {scanProgress && (
          <span className="ml-1 text-[13px] text-indigo animate-pulse">{scanProgress}</span>
        )}
      </div>

      {/* 統計卡片 */}
      <div className="mb-6 grid grid-cols-4 gap-3">
        {([
          { key: "critical", label: "Critical", color: "text-critical" },
          { key: "high", label: "High", color: "text-high" },
          { key: "medium", label: "Medium", color: "text-medium" },
          { key: "low", label: "Low", color: "text-low" },
        ] as const).map((c) => (
          <div
            key={c.key}
            className="rounded-lg border border-border bg-card p-4 text-center"
          >
            <div className={`text-[28px] font-bold leading-none ${c.color}`}>{sum(c.key)}</div>
            <div className="mt-1 text-xs uppercase text-muted-foreground">{c.label}</div>
          </div>
        ))}
      </div>

      {/* 歷史趨勢圖 */}
      <TrendChart />

      <h2 className="mb-3 text-base font-semibold">最近掃描</h2>
      {stats.map((s) => (
        <div
          key={s.scan.id}
          className="mb-3 cursor-pointer rounded-lg border border-border bg-card p-4 transition-colors hover:bg-accent"
          onClick={() => onOpen(s.scan.id)}
        >
          <div className="mb-2 flex items-center justify-between">
            <div>
              <div className="text-[15px] font-semibold">{s.scan.project_name}</div>
              <div className="text-xs text-muted-foreground">
                {s.scan.target} · {formatTime(s.scan.created_at)} · {formatDuration(s.scan)}
                {s.scan.scan_type === "profile" && (
                  <EngineBadge className="ml-1.5">profile</EngineBadge>
                )}
              </div>
            </div>
            <StatusBadge status={s.scan.status} />
          </div>
          <div className="flex items-center justify-between">
            <div className="flex flex-wrap gap-2">
              {s.critical > 0 && <SeverityBadge severity="CRITICAL" />}
              {s.high > 0 && (
                <span className="inline-flex items-center rounded bg-high px-2 py-0.5 text-xs font-semibold text-white">
                  {s.high}
                </span>
              )}
              {s.medium > 0 && (
                <span className="inline-flex items-center rounded bg-medium px-2 py-0.5 text-xs font-semibold text-white">
                  {s.medium}
                </span>
              )}
              {s.low > 0 && (
                <span className="inline-flex items-center rounded bg-low px-2 py-0.5 text-xs font-semibold text-white">
                  {s.low}
                </span>
              )}
            </div>
            <span className="text-xs text-muted-foreground">{s.findings} 個發現</span>
          </div>
        </div>
      ))}
    </div>
  );
}
