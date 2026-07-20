import { useEffect, useMemo, useState } from "react";
import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts";
import { api, type Project, type TrendPoint } from "@/lib/api";
import { formatTime } from "@/lib/constants";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

/* 歷史趨勢圖 新增 vs 修復 隨時間變化
   以 scan_findings 事件表逐對比對算出 added/resolved */
export function TrendChart() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [projectId, setProjectId] = useState("");
  const [points, setPoints] = useState<TrendPoint[]>([]);
  const [error, setError] = useState("");

  useEffect(() => {
    api.listProjects().then(({ projects }) => {
      setProjects(projects);
      if (projects.length > 0) setProjectId(projects[0].id);
    }).catch((e) => setError((e as Error).message));
  }, []);

  useEffect(() => {
    if (!projectId) return;
    api
      .trends(projectId)
      .then((t) => setPoints(t.points))
      .catch((e) => setError((e as Error).message));
  }, [projectId]);

  const data = useMemo(
    () =>
      points.map((p) => ({
        name: formatTime(p.created_at),
        新增: p.added,
        修復: p.resolved,
      })),
    [points],
  );

  return (
    <div className="rounded-lg border border-border bg-card p-4 mb-6">
      <div className="mb-3 flex items-center justify-between gap-2">
        <h2 className="text-sm font-semibold">歷史趨勢 新增 vs 修復</h2>
        {projects.length > 0 && (
          <Select value={projectId} onValueChange={setProjectId}>
            <SelectTrigger className="h-8 w-[220px] text-[13px]">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              {projects.map((p) => (
                <SelectItem key={p.id} value={p.id}>
                  {p.name}
                </SelectItem>
              ))}
            </SelectContent>
          </Select>
        )}
      </div>

      {error && (
        <div className="rounded-lg border border-critical/30 bg-critical/10 p-3 text-sm text-critical">
          {error}
        </div>
      )}

      {!error && points.length === 0 && (
        <div className="py-8 text-center text-sm text-muted-foreground">
          此專案需多次掃描才有趨勢資料
        </div>
      )}

      {!error && points.length > 0 && (
        <ResponsiveContainer width="100%" height={240}>
          <LineChart data={data} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" className="stroke-border" />
            <XAxis
              dataKey="name"
              tick={{ fontSize: 11 }}
              className="fill-muted-foreground"
            />
            <YAxis allowDecimals={false} tick={{ fontSize: 11 }} className="fill-muted-foreground" />
            <Tooltip
              contentStyle={{
                background: "var(--card)",
                border: "1px solid var(--border)",
                borderRadius: 8,
                fontSize: 12,
              }}
            />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Line
              type="monotone"
              dataKey="新增"
              stroke="var(--critical)"
              strokeWidth={2}
              dot={{ r: 3 }}
            />
            <Line
              type="monotone"
              dataKey="修復"
              stroke="var(--success)"
              strokeWidth={2}
              dot={{ r: 3 }}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
