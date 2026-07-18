import { useState, useEffect } from "react";
import {
  api,
  type Scan,
  type ScanDetail,
  type SBOMDiff,
  type SBOMPackage,
  type SBOMPackageChange,
} from "@/lib/api";
import { formatTime } from "@/lib/constants";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

/* PkgList 渲染新增或移除的套件明細 */
function PkgList({ pkgs }: { pkgs: SBOMPackage[] }) {
  return (
    <ul className="flex flex-col gap-1">
      {pkgs.map((p) => (
        <li key={p.purl || `${p.name}@${p.version}`} className="text-[13px]">
          <span className="font-medium">{p.name}</span>
          <span className="ml-1.5 font-mono text-xs text-muted-foreground">
            {p.version || "—"}
          </span>
        </li>
      ))}
    </ul>
  );
}

/* ChangeList 渲染版本變動的套件明細 old → new */
function ChangeList({ changes }: { changes: SBOMPackageChange[] }) {
  return (
    <ul className="flex flex-col gap-1">
      {changes.map((c) => (
        <li key={c.purl || c.name} className="text-[13px]">
          <span className="font-medium">{c.name}</span>
          <span className="ml-1.5 font-mono text-xs text-muted-foreground">
            {c.old_version} → {c.new_version}
          </span>
        </li>
      ))}
    </ul>
  );
}

/*
	SBOMDiffSection 與同 project 另一次掃描的 SBOM 比較 供應鏈漂移

僅列出同 project 且已產生 SBOM 的掃描 預設選時間上最近的前一次
比較目標本身無 SBOM 時不渲染 由父層以 sbom.available 控制
*/
export function SBOMDiffSection({ scan }: { scan: ScanDetail }) {
  const [others, setOthers] = useState<Scan[]>([]);
  const [compareTo, setCompareTo] = useState("");
  const [diff, setDiff] = useState<SBOMDiff | null>(null);
  const [error, setError] = useState("");

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
      setError("");
      return;
    }
    api
      .getScanSBOMDiff(compareTo, scan.id)
      .then((d) => {
        setDiff(d);
        setError("");
      })
      .catch((e) => {
        setDiff(null);
        setError((e as Error).message);
      });
  }, [compareTo, scan.id]);

  if (others.length === 0) return null;

  return (
    <div className="mt-3 rounded-lg border border-border bg-card p-4">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-xs text-muted-foreground">與其他掃描比較 SBOM</span>
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
              移除 {diff.removed.length}
            </span>
            <span className="text-xs font-semibold text-medium">
              變動 {diff.changed.length}
            </span>
            <span className="text-xs font-semibold text-muted-foreground">
              不變 {diff.unchanged}
            </span>
          </span>
        )}
      </div>

      {error && (
        <div className="mt-3 rounded-lg border border-border bg-background p-3 text-[13px] text-muted-foreground">
          {error}
        </div>
      )}

      {diff &&
        (diff.added.length > 0 ||
          diff.removed.length > 0 ||
          diff.changed.length > 0) && (
          <div className="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-3">
            {diff.added.length > 0 && (
              <div className="rounded-md border-l-[3px] border-l-critical bg-background p-3">
                <div className="mb-2 text-xs font-semibold uppercase text-muted-foreground">
                  新增套件
                </div>
                <PkgList pkgs={diff.added} />
              </div>
            )}
            {diff.removed.length > 0 && (
              <div className="rounded-md border-l-[3px] border-l-success bg-background p-3">
                <div className="mb-2 text-xs font-semibold uppercase text-muted-foreground">
                  移除套件
                </div>
                <PkgList pkgs={diff.removed} />
              </div>
            )}
            {diff.changed.length > 0 && (
              <div className="rounded-md border-l-[3px] border-l-medium bg-background p-3">
                <div className="mb-2 text-xs font-semibold uppercase text-muted-foreground">
                  版本變動
                </div>
                <ChangeList changes={diff.changed} />
              </div>
            )}
          </div>
        )}
    </div>
  );
}
