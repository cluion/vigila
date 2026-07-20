import { useState, useEffect, useRef } from "react";
import { api, subscribeEvents, type ScanStat, type Engine } from "@/lib/api";
import { formatTime, formatDuration } from "@/lib/constants";
import { SeverityBadge, StatusBadge, EngineBadge } from "@/components/badges";
import { TrendChart } from "@/components/TrendChart";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Trash2, Upload } from "lucide-react";
import { cn } from "@/lib/utils";

/* 掃描列表頁 儀表板 */
export function ScanListPage({ onOpen }: { onOpen: (id: string) => void }) {
  const [stats, setStats] = useState<ScanStat[] | null>(null);
  const [error, setError] = useState("");
  const [scanProgress, setScanProgress] = useState<string>("");
  const [scanTarget, setScanTarget] = useState("");
  const [engines, setEngines] = useState<Engine[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [exclude, setExclude] = useState("");
  const fileInputRef = useRef<HTMLInputElement>(null);

  const refresh = () => {
    api
      .stats()
      .then((s) => setStats(s.recent_scans))
      .catch((e) => setError((e as Error).message));
  };

  useEffect(() => {
    api
      .listEngines()
      .then((r) => setEngines(r.engines))
      .catch(() => setEngines([]));
  }, []);

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

  const toggleEngine = (name: string) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(name)) next.delete(name);
      else next.add(name);
      return next;
    });
  };

  const triggerScan = async () => {
    if (!scanTarget.trim()) return;
    setScanProgress("啟動中 ...");
    /* 未勾選任何引擎＝全部適用者 勾選則只跑選定的 排除以空白或逗號分隔 */
    const excludes = exclude
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    await api.startScan(scanTarget.trim(), {
      engines: selected.size > 0 ? [...selected] : undefined,
      exclude: excludes.length > 0 ? excludes : undefined,
    });
  };

  /* 上傳壓縮包掃描 選檔後立即上傳 共用目前的引擎多選與排除設定 */
  const onUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    /* 重置 input value 讓相同檔案可重複選取 */
    e.target.value = "";
    setScanProgress(`上傳中 ${file.name} ...`);
    const excludes = exclude
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    try {
      await api.uploadAndScan(file, {
        engines: selected.size > 0 ? [...selected] : undefined,
        exclude: excludes.length > 0 ? excludes : undefined,
      });
      /* 上傳成功後 SSE 會接手進度顯示 scan_started/scan_completed */
    } catch (err) {
      setScanProgress("");
      setError((err as Error).message);
    }
  };

  /* 刪除掃描 阻止冒泡避免開啟詳情 確認後刪除並刷新 */
  const removeScan = async (e: React.MouseEvent, id: string, name: string) => {
    e.stopPropagation();
    if (!window.confirm(`確定刪除 ${name} 這次掃描？連帶清除其漏洞與 SBOM 結果 無法復原。`)) {
      return;
    }
    try {
      await api.deleteScan(id);
      refresh();
    } catch (err) {
      setError((err as Error).message);
    }
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
        <input
          ref={fileInputRef}
          type="file"
          accept=".zip,.tar.gz,.tgz"
          className="hidden"
          onChange={onUpload}
        />
        <Button
          variant="outline"
          onClick={() => fileInputRef.current?.click()}
          disabled={!!scanProgress}
          title="上傳 zip 或 tar.gz 壓縮包掃描 上限 100MB"
        >
          <Upload className="size-4" />
          上傳
        </Button>
        {scanProgress && (
          <span className="ml-1 text-[13px] text-indigo animate-pulse">{scanProgress}</span>
        )}
      </div>

      {/* 引擎選擇 未勾選＝全部適用者 勾選則只跑選定的 */}
      {engines.length > 0 && (
        <div className="mb-5 flex flex-wrap items-center gap-1.5">
          <span className="mr-1 text-xs text-muted-foreground">
            引擎{selected.size === 0 ? "（全部適用者）" : `（已選 ${selected.size}）`}：
          </span>
          {engines.map((e) => {
            const on = selected.has(e.name);
            return (
              <button
                key={e.name}
                onClick={() => toggleEngine(e.name)}
                className={cn(
                  "rounded-full border px-2.5 py-0.5 text-xs transition-colors",
                  on
                    ? "border-indigo bg-indigo/15 text-indigo"
                    : "border-border text-muted-foreground hover:bg-accent",
                )}
                title={`${e.category} · ${e.target_kinds.join(" ")}`}
              >
                {e.name}
              </button>
            );
          })}
          {selected.size > 0 && (
            <button
              onClick={() => setSelected(new Set())}
              className="ml-1 text-xs text-muted-foreground underline hover:text-foreground"
            >
              清除
            </button>
          )}
        </div>
      )}

      {/* 排除路徑 空白或逗號分隔 gitleaks 不支援 */}
      <div className="mb-5 flex items-center gap-2">
        <span className="text-xs text-muted-foreground whitespace-nowrap">排除路徑：</span>
        <Input
          type="text"
          className="min-w-[200px] flex-1 text-[13px]"
          placeholder="以空白或逗號分隔 如 node_modules vendor（支援 semgrep trivy checkov）"
          value={exclude}
          onChange={(e) => setExclude(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && triggerScan()}
        />
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
            <div className="flex items-center gap-2">
              <StatusBadge status={s.scan.status} />
              <button
                onClick={(e) => removeScan(e, s.scan.id, s.scan.project_name)}
                className="text-muted-foreground transition-colors hover:text-critical"
                title="刪除掃描"
                aria-label="刪除掃描"
              >
                <Trash2 className="size-4" />
              </button>
            </div>
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
