import { useState, useEffect } from "react";
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
} from "@/components/ui/command";
import { api, type ScanStat } from "@/lib/api";
import { formatTime } from "@/lib/constants";
import { useTheme } from "@/lib/theme";

interface CommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  onNavigate: (path: string) => void;
  onTriggerScan: () => void;
}

/* Command Palette cmd+k 快速導航與動作 */
export function CommandPalette({
  open,
  onOpenChange,
  onNavigate,
  onTriggerScan,
}: CommandPaletteProps) {
  const [recent, setRecent] = useState<ScanStat[]>([]);
  const { resolved, toggle } = useTheme();

  useEffect(() => {
    if (!open) return;
    api
      .stats()
      .then((s) => setRecent(s.recent_scans.slice(0, 6)))
      .catch(() => setRecent([]));
  }, [open]);

  const run = (fn: () => void) => {
    fn();
    onOpenChange(false);
  };

  return (
    <CommandDialog
      open={open}
      onOpenChange={onOpenChange}
      title="指令面板"
      description="輸入指令或搜尋掃描"
    >
      <CommandInput placeholder="輸入指令或搜尋掃描..." />
      <CommandList>
        <CommandEmpty>沒有符合的結果</CommandEmpty>

        <CommandGroup heading="動作">
          <CommandItem onSelect={() => run(() => onNavigate("/"))}>
            🏠 回到儀表板
          </CommandItem>
          <CommandItem onSelect={() => run(onTriggerScan)}>🚀 觸發新掃描</CommandItem>
          <CommandItem onSelect={() => run(() => onNavigate("/engines"))}>
            🔧 引擎管理
          </CommandItem>
          <CommandItem onSelect={() => run(toggle)}>
            {resolved === "dark" ? "☀️ 切換為亮色模式" : "🌙 切換為暗色模式"}
          </CommandItem>
        </CommandGroup>

        {recent.length > 0 && (
          <CommandGroup heading="最近掃描">
            {recent.map((s) => (
              <CommandItem
                key={s.scan.id}
                value={`${s.scan.project_name} ${formatTime(s.scan.created_at)} ${s.scan.id}`}
                onSelect={() => run(() => onNavigate(`/scans/${s.scan.id}`))}
                className="justify-between"
              >
                <span className="truncate">
                  {s.scan.project_name} · {formatTime(s.scan.created_at)}
                </span>
                <span className="shrink-0 text-xs text-muted-foreground">
                  {s.findings} 個發現
                </span>
              </CommandItem>
            ))}
          </CommandGroup>
        )}
      </CommandList>
    </CommandDialog>
  );
}
