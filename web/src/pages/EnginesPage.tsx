import { useState, useEffect } from "react";
import { api, type Engine } from "@/lib/api";
import { EngineBadge } from "@/components/badges";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

/* 引擎面板 唯讀顯示已註冊引擎的類別 可接受目標型態與安裝狀態 */
export function EnginesPage() {
  const [engines, setEngines] = useState<Engine[] | null>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    api
      .listEngines()
      .then((r) => setEngines(r.engines))
      .catch((e) => setError((e as Error).message));
  }, []);

  if (error)
    return (
      <div className="rounded-lg border border-critical/30 bg-critical/10 p-4 text-sm text-critical">
        {error}
      </div>
    );
  if (!engines)
    return <div className="py-12 text-center text-sm text-muted-foreground">載入中</div>;

  const installedCount = engines.filter((e) => e.installed).length;

  return (
    <div>
      <div className="mb-4">
        <h2 className="text-base font-semibold">掃描引擎</h2>
        <p className="mt-1 text-[13px] text-muted-foreground">
          共 {engines.length} 個引擎 已安裝 {installedCount} 個。未安裝的引擎需自行加入 PATH
          後才能使用。
        </p>
      </div>

      <div className="rounded-lg border border-border bg-card">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>引擎</TableHead>
              <TableHead>類別</TableHead>
              <TableHead>目標型態</TableHead>
              <TableHead>狀態</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {engines.map((e) => (
              <TableRow key={e.name}>
                <TableCell className="font-medium">{e.name}</TableCell>
                <TableCell>
                  <EngineBadge>{e.category}</EngineBadge>
                </TableCell>
                <TableCell className="text-[13px] text-muted-foreground">
                  {e.target_kinds.join(" ")}
                </TableCell>
                <TableCell>
                  {e.installed ? (
                    <span className="inline-flex items-center gap-1 text-[13px] text-success">
                      <span className="size-1.5 rounded-full bg-success" />
                      已安裝
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-[13px] text-muted-foreground">
                      <span className="size-1.5 rounded-full bg-muted-foreground/50" />
                      未安裝
                    </span>
                  )}
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
