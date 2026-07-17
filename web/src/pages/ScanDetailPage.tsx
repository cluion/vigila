import { useState, useEffect, useMemo } from "react";
import { api, subscribeEvents, type ScanDetail, type Finding } from "@/lib/api";
import { SEVERITIES, FINDING_STATUSES, formatTime, formatDuration } from "@/lib/constants";
import {
  SeverityBadge,
  StatusBadge,
  FindingStatusBadge,
  EngineBadge,
} from "@/components/badges";
import { DiffSection } from "@/components/DiffSection";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

const ENGINE_RUN_BORDER: Record<string, string> = {
  completed: "border-l-success",
  running: "border-l-indigo",
  failed: "border-l-critical",
};

/* 掃描詳情頁 含引擎卡 findings 篩選排序 與一鍵重掃 */
export function ScanDetailPage({
  scanId,
  onBack,
  onNavigateScan,
}: {
  scanId: string;
  onBack: () => void;
  onNavigateScan: (id: string) => void;
}) {
  const [scan, setScan] = useState<ScanDetail | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [error, setError] = useState("");
  const [rescanMsg, setRescanMsg] = useState("");
  const [rescanNewId, setRescanNewId] = useState<string>("");

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
      setFindings((prev) =>
        prev.map((f) => (f.id === id ? { ...f, status: updated.status } : f)),
      );
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
      .catch((e) => setError((e as Error).message));
  }, [scanId]);

  /* 一鍵重掃 訂閱 SSE 觀察新掃描進度與 scan_id */
  const rescan = async () => {
    if (!scan) return;
    setRescanMsg("重掃已啟動 ...");
    await api.startScan(scan.target, scan.profile || undefined);
  };

  useEffect(() => {
    /* 訂閱 SSE 重掃時捕捉新 scan_id 並可導航 */
    const unsub = subscribeEvents((type, data) => {
      if (type === "scan_started" && scan && data.target === scan.target) {
        setRescanNewId(data.scan_id || "");
        setRescanMsg("重掃進行中 ...");
      } else if (type === "scan_completed" && scan && data.target === scan.target) {
        setRescanMsg("重掃完成");
      }
    });
    return unsub;
  }, [scan]);

  /* 引擎列表 供篩選下拉 */
  const engines = useMemo(
    () => Array.from(new Set(findings.map((f) => f.engine))),
    [findings],
  );

  /* 篩選與排序後的 findings */
  const filtered = useMemo(() => {
    let out = [...findings];

    if (severityFilter) out = out.filter((f) => f.severity === severityFilter);
    if (engineFilter) out = out.filter((f) => f.engine === engineFilter);
    if (statusFilter) out = out.filter((f) => f.status === statusFilter);
    if (search.trim()) {
      const q = search.toLowerCase();
      out = out.filter(
        (f) =>
          f.title.toLowerCase().includes(q) ||
          f.rule_id.toLowerCase().includes(q) ||
          (f.file_path || "").toLowerCase().includes(q) ||
          (f.url || "").toLowerCase().includes(q) ||
          (f.host || "").toLowerCase().includes(q) ||
          (f.description || "").toLowerCase().includes(q),
      );
    }

    if (sortBy === "severity") {
      const rank: Record<string, number> = {
        CRITICAL: 0,
        HIGH: 1,
        MEDIUM: 2,
        LOW: 3,
        UNKNOWN: 4,
      };
      out.sort((a, b) => (rank[a.severity] ?? 9) - (rank[b.severity] ?? 9));
    } else if (sortBy === "engine") {
      out.sort((a, b) => a.engine.localeCompare(b.engine));
    } else if (sortBy === "file") {
      out.sort((a, b) => (a.file_path || "").localeCompare(b.file_path || ""));
    }

    return out;
  }, [findings, severityFilter, engineFilter, statusFilter, search, sortBy]);

  if (error)
    return (
      <div className="rounded-lg border border-critical/30 bg-critical/10 p-4 text-sm text-critical">
        {error}
      </div>
    );
  if (!scan)
    return <div className="py-12 text-center text-sm text-muted-foreground">載入中</div>;

  return (
    <div>
      <a
        className="mb-4 inline-block text-sm text-muted-foreground hover:text-indigo"
        href="#/"
        onClick={(e) => {
          e.preventDefault();
          onBack();
        }}
      >
        ← 返回列表
      </a>

      <div className="mb-3 rounded-lg border border-border bg-card p-4">
        <div className="mb-2 flex items-center justify-between gap-2">
          <div>
            <div className="text-[15px] font-semibold">{scan.project_name}</div>
            <div className="text-xs text-muted-foreground">
              {scan.target} · {formatTime(scan.created_at)} · {formatDuration(scan)}
              {scan.profile && <EngineBadge className="ml-1.5">{scan.profile}</EngineBadge>}
            </div>
          </div>
          <div className="flex items-center gap-2">
            {rescanMsg && (
              <span className="text-xs text-indigo animate-pulse">
                {rescanMsg}
                {rescanNewId && rescanMsg === "重掃完成" && (
                  <button
                    className="ml-1 underline hover:opacity-80"
                    onClick={() => onNavigateScan(rescanNewId)}
                  >
                    查看新掃描
                  </button>
                )}
              </span>
            )}
            <Button variant="outline" size="sm" onClick={rescan} disabled={!!rescanMsg}>
              一鍵重掃
            </Button>
            <StatusBadge status={scan.status} />
          </div>
        </div>

        {/* 引擎執行卡 */}
        {scan.engine_runs.length > 0 && (
          <div className="mt-3 flex flex-wrap gap-2">
            {scan.engine_runs.map((r) => (
              <div
                key={r.id}
                className={cn(
                  "inline-flex items-center gap-1.5 rounded-md border border-l-[3px] border-border bg-muted px-2.5 py-1.5",
                  ENGINE_RUN_BORDER[r.status] || "border-l-muted",
                )}
              >
                <EngineBadge>{r.engine}</EngineBadge>
                <span className="text-xs text-muted-foreground">{r.category}</span>
                <span className="text-xs text-muted-foreground">· {r.status}</span>
                {r.duration_ms != null && (
                  <span className="text-xs text-muted-foreground">· {r.duration_ms}ms</span>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* 與其他掃描比較 */}
      <DiffSection scan={scan} />

      {/* 篩選工具列 */}
      <div className="my-4 flex flex-wrap items-center gap-2">
        <Input
          type="text"
          className="min-w-[200px] flex-1"
          placeholder="搜尋漏洞 規則 檔案"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="h-9 w-[140px] text-[13px]">
            <SelectValue placeholder="全部嚴重度" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部嚴重度</SelectItem>
            {SEVERITIES.map((s) => (
              <SelectItem key={s} value={s}>
                {s}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={engineFilter} onValueChange={(v) => setEngineFilter(v === "all" ? "" : v)}>
          <SelectTrigger className="h-9 w-[140px] text-[13px]">
            <SelectValue placeholder="全部引擎" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部引擎</SelectItem>
            {engines.map((e) => (
              <SelectItem key={e} value={e}>
                {e}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={(v) => setStatusFilter(v === "all" ? "" : v)}>
          <SelectTrigger className="h-9 w-[140px] text-[13px]">
            <SelectValue placeholder="全部狀態" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">全部狀態</SelectItem>
            {FINDING_STATUSES.map((s) => (
              <SelectItem key={s.value} value={s.value}>
                {s.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={sortBy} onValueChange={setSortBy}>
          <SelectTrigger className="h-9 w-[150px] text-[13px]">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="severity">依嚴重度排序</SelectItem>
            <SelectItem value="engine">依引擎排序</SelectItem>
            <SelectItem value="file">依檔案排序</SelectItem>
          </SelectContent>
        </Select>
        <span className="ml-auto text-xs text-muted-foreground">
          {filtered.length} / {findings.length}
        </span>
      </div>

      <h2 className="my-4 text-base font-semibold">漏洞清單</h2>

      {filtered.length === 0 ? (
        <div className="py-12 text-center text-sm text-muted-foreground">
          {findings.length === 0 ? "沒有發現" : "沒有符合篩選條件的漏洞"}
        </div>
      ) : (
        <div className="overflow-hidden rounded-lg border border-border">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>嚴重度</TableHead>
                <TableHead>漏洞</TableHead>
                <TableHead>引擎</TableHead>
                <TableHead>位置</TableHead>
                <TableHead>狀態</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((f) => (
                <TableRow key={f.id}>
                  <TableCell className="align-top text-xs font-semibold whitespace-nowrap">
                    <SeverityBadge severity={f.severity} />
                    {f.cvss_score != null && (
                      <div className="mt-0.5 text-xs text-muted-foreground">
                        CVSS {f.cvss_score}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="align-top">
                    <div className="mb-0.5 font-medium">{f.title}</div>
                    <div className="font-mono text-xs text-muted-foreground">{f.rule_id}</div>
                    {f.cwe && (
                      <div className="mt-0.5 text-xs text-muted-foreground">{f.cwe}</div>
                    )}
                    {f.fixed_version && (
                      <div className="mt-1 text-xs font-medium text-success">
                        修復版本 {f.fixed_version}
                      </div>
                    )}
                    {f.snippet && (
                      <div className="mt-1.5 whitespace-pre-wrap break-all rounded bg-background p-2 font-mono text-xs text-muted-foreground">
                        {f.snippet}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="align-top">
                    <EngineBadge>{f.engine}</EngineBadge>
                    <div className="text-xs text-muted-foreground">{f.category}</div>
                  </TableCell>
                  <TableCell className="align-top font-mono text-xs text-muted-foreground">
                    {f.file_path && <div>{f.file_path}</div>}
                    {f.start_line && <div>第 {f.start_line} 行</div>}
                    {f.url && <div>{f.url}</div>}
                    {f.host && (
                      <div>
                        {f.host}
                        {f.port ? `:${f.port}` : ""}
                      </div>
                    )}
                    {f.pkg_name && (
                      <div>
                        {f.pkg_name} @ {f.installed_version}
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="align-top whitespace-nowrap">
                    <FindingStatusBadge status={f.status} />
                    <div className="mt-1.5 flex gap-1">
                      {f.status === "open" ? (
                        <>
                          <Button
                            variant="outline"
                            size="xs"
                            onClick={() => updateStatus(f.id, "resolved")}
                          >
                            解決
                          </Button>
                          <Button
                            variant="outline"
                            size="xs"
                            onClick={() => updateStatus(f.id, "ignored")}
                          >
                            忽略
                          </Button>
                        </>
                      ) : (
                        <Button
                          variant="outline"
                          size="xs"
                          onClick={() => updateStatus(f.id, "open")}
                        >
                          重開
                        </Button>
                      )}
                    </div>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}
