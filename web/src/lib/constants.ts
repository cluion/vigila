/* 全域常數 與格式化輔助函數 */

import type { ScanDetail, Scan, Finding } from "@/lib/api";

export const SEVERITIES = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"];

export const FINDING_STATUSES = [
  { value: "open", label: "未處理" },
  { value: "resolved", label: "已解決" },
  { value: "ignored", label: "已忽略" },
] as const;

/* 掃描與引擎執行狀態的中文標籤 對齊全站繁中介面 */
export const SCAN_STATUS_LABELS: Record<string, string> = {
  pending: "等待中",
  running: "執行中",
  completed: "已完成",
  failed: "失敗",
};

export function scanStatusLabel(status: string): string {
  return SCAN_STATUS_LABELS[status] || status;
}

export function formatTime(s: string | null): string {
  if (!s) return "—";
  return new Date(s).toLocaleString("zh-TW", { hour12: false });
}

export function formatDuration(scan: ScanDetail | Scan): string {
  if (!scan.started_at || !scan.completed_at) return "—";
  const ms = new Date(scan.completed_at).getTime() - new Date(scan.started_at).getTime();
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

/* diffFindingLocation 組出 finding 的位置描述 */
export function diffFindingLocation(f: Finding): string {
  if (f.file_path) {
    return f.start_line ? `${f.file_path}:${f.start_line}` : f.file_path;
  }
  if (f.url) {
    return f.url;
  }
  if (f.host) {
    return f.port ? `${f.host}:${f.port}` : f.host;
  }
  if (f.pkg_name) {
    return f.installed_version ? `${f.pkg_name}@${f.installed_version}` : f.pkg_name;
  }
  return "";
}
