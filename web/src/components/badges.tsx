import { cn } from "@/lib/utils";
import { FINDING_STATUSES } from "@/lib/constants";

/* 嚴重度徽章 實心底色 + 白字
   使用註冊的主題色 critical/high/medium/low/unknown（兩主題一致） */
const SEVERITY_CLASS: Record<string, string> = {
  CRITICAL: "bg-critical text-white",
  HIGH: "bg-high text-white",
  MEDIUM: "bg-medium text-white",
  LOW: "bg-low text-white",
  UNKNOWN: "bg-unknown text-white",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span
      className={cn(
        "inline-flex w-fit items-center gap-1 rounded px-2 py-0.5 text-xs font-semibold whitespace-nowrap",
        SEVERITY_CLASS[severity] || SEVERITY_CLASS.UNKNOWN,
      )}
    >
      {severity}
    </span>
  );
}

const STATUS_CLASS: Record<string, string> = {
  completed: "bg-success text-white",
  running: "bg-indigo text-white",
  failed: "bg-critical text-white",
};

/* 掃描狀態徽章 completed/running/failed 有底色 其餘僅外框 */
export function StatusBadge({ status }: { status: string }) {
  const cls = STATUS_CLASS[status];
  return (
    <span
      className={cn(
        "inline-block rounded px-2 py-0.5 text-[11px] font-semibold uppercase whitespace-nowrap",
        cls || "border border-border text-muted-foreground",
      )}
    >
      {status}
    </span>
  );
}

const FINDING_STATUS_CLASS: Record<string, string> = {
  open: "bg-indigo/15 text-indigo",
  resolved: "bg-success/15 text-success",
  ignored: "bg-muted text-muted-foreground",
};

/* 漏洞狀態徽章 open/resolved/ignored 中文標籤 */
export function FindingStatusBadge({ status }: { status: string }) {
  const label = FINDING_STATUSES.find((s) => s.value === status)?.label || status;
  return (
    <span
      className={cn(
        "inline-block rounded px-2 py-0.5 text-[11px] font-semibold",
        FINDING_STATUS_CLASS[status] || FINDING_STATUS_CLASS.ignored,
      )}
    >
      {label}
    </span>
  );
}

/* 引擎徽章 淡色底 標示引擎/分類/profile 等 */
export function EngineBadge({ children, className }: { children: React.ReactNode; className?: string }) {
  return (
    <span
      className={cn(
        "inline-block rounded-[3px] bg-muted px-1.5 py-px text-[11px] text-muted-foreground",
        className,
      )}
    >
      {children}
    </span>
  );
}
