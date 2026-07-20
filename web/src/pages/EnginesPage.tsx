import { useState, useEffect } from "react";
import { api, type Engine } from "@/lib/api";
import { EngineBadge } from "@/components/badges";
import { Check, Copy, Download, ExternalLink } from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { cn } from "@/lib/utils";

/*
	DockerToggle 勾選引擎是否以 docker 執行 切換後回呼重載

不支援 docker 的引擎顯示 — 勾選會寫入 .env 的 COMPOSE_PROFILES 並蓋過偶然在 PATH 的系統版
*/
function DockerToggle({
  engine,
  onChanged,
}: {
  engine: Engine;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  if (!engine.docker_capable) {
    return <span className="text-xs text-muted-foreground">—</span>;
  }

  const toggle = async () => {
    setBusy(true);
    setErr("");
    try {
      await api.setEngineDocker(engine.name, !engine.docker_enabled);
      onChanged();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex items-center gap-2">
      <button
        role="switch"
        aria-checked={engine.docker_enabled}
        aria-label={`${engine.name} 以 docker 執行`}
        disabled={busy}
        onClick={toggle}
        className={cn(
          "relative inline-flex h-5 w-9 items-center rounded-full transition-colors disabled:opacity-50",
          engine.docker_enabled ? "bg-sky-500" : "bg-muted-foreground/30",
        )}
      >
        <span
          className={cn(
            "inline-block size-4 transform rounded-full bg-white shadow transition-transform",
            engine.docker_enabled ? "translate-x-4" : "translate-x-0.5",
          )}
        />
      </button>
      {err && (
        <span className="text-xs text-critical" title={err}>
          失敗
        </span>
      )}
    </div>
  );
}

/*
	InstallButton 一鍵安裝 managed binary 點擊後同步下載 完成後重載清單

僅 installable 引擎顯示 下載需數十秒 期間顯示安裝中 並禁用按鈕防重複點擊
*/
function InstallButton({
  engine,
  onChanged,
}: {
  engine: Engine;
  onChanged: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  const install = async () => {
    setBusy(true);
    setErr("");
    try {
      await api.installEngine(engine.name);
      onChanged();
    } catch (e) {
      setErr((e as Error).message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex items-center gap-1.5">
      <button
        onClick={install}
        disabled={busy}
        className="inline-flex items-center gap-1 rounded border border-border bg-card px-2 py-1 text-xs text-foreground transition-colors hover:bg-muted disabled:opacity-50"
        title="下載官方 binary 到 managed 目錄"
      >
        <Download className="size-3" />
        {busy ? "安裝中" : "安裝"}
      </button>
      {err && (
        <span className="text-xs text-critical" title={err}>
          失敗
        </span>
      )}
    </div>
  );
}

/* CopyButton 複製安裝指令 複製後短暫顯示打勾 */
function CopyButton({ text }: { text: string }) {
  const [copied, setCopied] = useState(false);
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      /* clipboard 不可用時忽略 */
    }
  };
  return (
    <button
      onClick={copy}
      className="text-muted-foreground hover:text-foreground"
      title="複製"
    >
      {copied ? <Check className="size-3.5 text-success" /> : <Copy className="size-3.5" />}
    </button>
  );
}

/* sourceMeta 把來源轉為顯示標籤與圓點色 */
function sourceMeta(source: Engine["source"]): { label: string; dot: string; text: string } {
  switch (source) {
    case "system":
      return { label: "本機系統", dot: "bg-success", text: "text-success" };
    case "managed":
      return { label: "managed 下載", dot: "bg-indigo", text: "text-indigo" };
    case "docker":
      return { label: "docker 容器", dot: "bg-sky-500", text: "text-sky-500" };
    default:
      return { label: "未安裝", dot: "bg-muted-foreground/50", text: "text-muted-foreground" };
  }
}

/* 引擎面板 唯讀顯示已註冊引擎的類別 目標型態 版本與來源 */
export function EnginesPage() {
  const [engines, setEngines] = useState<Engine[] | null>(null);
  const [error, setError] = useState("");

  const load = () => {
    api
      .listEngines()
      .then((r) => setEngines(r.engines))
      .catch((e) => setError((e as Error).message));
  };

  useEffect(() => {
    load();
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
          共 {engines.length} 個引擎 已安裝 {installedCount} 個。未安裝的引擎可點一鍵安裝下載官方
          binary（gitleaks grype trivy trufflehog nuclei osv-scanner）或依安裝指引自行處理。開啟
          Docker 開關即以官方容器執行 免本機安裝 並蓋過偶然在 PATH 的系統版。
        </p>
      </div>

      <div className="rounded-lg border border-border bg-card">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>引擎</TableHead>
              <TableHead>類別</TableHead>
              <TableHead>目標型態</TableHead>
              <TableHead>版本</TableHead>
              <TableHead>來源</TableHead>
              <TableHead>Docker</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {engines.map((e) => {
              const src = sourceMeta(e.source);
              return (
                <TableRow key={e.name}>
                  <TableCell className="font-medium">{e.name}</TableCell>
                  <TableCell>
                    <EngineBadge>{e.category}</EngineBadge>
                  </TableCell>
                  <TableCell className="text-[13px] text-muted-foreground">
                    {e.target_kinds.join(" ")}
                  </TableCell>
                  <TableCell className="font-mono text-[13px] tabular-nums">
                    {e.version || <span className="text-muted-foreground">—</span>}
                  </TableCell>
                  <TableCell>
                    <div className="space-y-1.5">
                      <span className={`inline-flex items-center gap-1 text-[13px] ${src.text}`}>
                        <span className={`size-1.5 rounded-full ${src.dot}`} />
                        {src.label}
                      </span>
                      {!e.installed && (
                        <div className="flex flex-wrap items-center gap-2">
                          <code className="rounded bg-muted px-1.5 py-0.5 font-mono text-xs">
                            {e.install_hint.command}
                          </code>
                          <CopyButton text={e.install_hint.command} />
                          {e.installable && <InstallButton engine={e} onChanged={load} />}
                          <a
                            href={e.install_hint.docs_url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="inline-flex items-center gap-0.5 text-xs text-indigo hover:underline"
                          >
                            文件
                            <ExternalLink className="size-3" />
                          </a>
                        </div>
                      )}
                    </div>
                  </TableCell>
                  <TableCell>
                    <DockerToggle engine={e} onChanged={load} />
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
    </div>
  );
}
