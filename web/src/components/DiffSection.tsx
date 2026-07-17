import { useState, useEffect } from "react";
import {
  api,
  type Scan,
  type ScanDetail,
  type Finding,
  type ScanDiff,
} from "@/lib/api";
import { formatTime, diffFindingLocation } from "@/lib/constants";
import { SeverityBadge, EngineBadge } from "@/components/badges";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { cn } from "@/lib/utils";

/* DiffFindingList 渲染 diff 的 findings 明細 */
function DiffFindingList({ findings }: { findings: Finding[] }) {
  return (
    <ul className="flex flex-col gap-1.5">
      {findings.map((f) => (
        <li key={f.id} className="flex flex-wrap items-center gap-2 text-[13px]">
          <SeverityBadge severity={f.severity} />
          <EngineBadge>{f.engine}</EngineBadge>
          <span>{f.title}</span>
          <span className="font-mono text-xs text-muted-foreground">
            {diffFindingLocation(f)}
          </span>
        </li>
      ))}
    </ul>
  );
}

/* DiffSection 與同 project 的另一次掃描比較 新增/消失/不變 */
export function DiffSection({ scan }: { scan: ScanDetail }) {
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
          (s) => s.project_id === scan.project_id && s.id !== scan.id,
        );
        setOthers(sameProject);
        const prev = sameProject.find((s) => s.created_at < scan.created_at);
        setCompareTo(prev ? prev.id : "");
      })
      .catch((e) => setError((e as Error).message));
  }, [scan.id, scan.project_id, scan.created_at]);

  useEffect(() => {
    if (!compareTo) {
      setDiff(null);
      return;
    }
    api
      .getScanDiff(compareTo, scan.id)
      .then(setDiff)
      .catch((e) => setError((e as Error).message));
  }, [compareTo, scan.id]);

  if (others.length === 0) return null;

  return (
    <div className="rounded-lg border border-border bg-card p-4 mb-3">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">與其他掃描比較</span>
        <Select value={compareTo} onValueChange={setCompareTo}>
          <SelectTrigger className="h-8 w-[280px] text-[13px]">
            <SelectValue placeholder="選擇掃描" />
          </SelectTrigger>
          <SelectContent>
            {others.map((s) => (
              <SelectItem key={s.id} value={s.id}>
                {formatTime(s.created_at)} · {s.id.slice(-8)}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
        {diff && (
          <span className="flex items-center gap-2">
            <span className="text-xs font-semibold text-critical">
              新增 {diff.added.length}
            </span>
            <span className="text-xs font-semibold text-success">
              消失 {diff.removed.length}
            </span>
            <span className="text-xs font-semibold text-muted-foreground">
              不變 {diff.unchanged}
            </span>
          </span>
        )}
      </div>

      {error && (
        <div className="mt-3 rounded-lg border border-critical/30 bg-critical/10 p-3 text-sm text-critical">
          {error}
        </div>
      )}

      {diff && (diff.added.length > 0 || diff.removed.length > 0) && (
        <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2">
          {diff.added.length > 0 && (
            <div className="rounded-md border-l-[3px] border-l-critical bg-background p-3">
              <div className="mb-2 text-xs font-semibold uppercase text-muted-foreground">
                新增漏洞
              </div>
              <DiffFindingList findings={diff.added} />
            </div>
          )}
          {diff.removed.length > 0 && (
            <div className={cn("rounded-md border-l-[3px] border-l-success bg-background p-3")}>
              <div className="mb-2 text-xs font-semibold uppercase text-muted-foreground">
                消失漏洞
              </div>
              <DiffFindingList findings={diff.removed} />
            </div>
          )}
        </div>
      )}
    </div>
  );
}
