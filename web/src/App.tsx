import { useState, useEffect } from "react";
import { useHashRoute } from "@/hooks/useHashRoute";
import { ThemeProvider } from "@/lib/theme";
import { ScanListPage } from "@/pages/ScanListPage";
import { ScanDetailPage } from "@/pages/ScanDetailPage";
import { EnginesPage } from "@/pages/EnginesPage";
import { ThemeToggle } from "@/components/ThemeToggle";
import { CommandPalette } from "@/components/CommandPalette";
import { Button } from "@/components/ui/button";
import { Command as CommandIcon } from "lucide-react";

function AppInner() {
  const [route, navigate] = useHashRoute();
  const [cmdOpen, setCmdOpen] = useState(false);

  /* 全域 Cmd/Ctrl+K 開啟 command palette */
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCmdOpen((o) => !o);
      }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const scanMatch = route.match(/^\/scans\/(.+)$/);
  const isEngines = route === "/engines";
  /* 掃描列表與掃描詳情都歸在「掃描」分頁下 */
  const activeNav = isEngines ? "engines" : "scans";

  return (
    <div className="mx-auto max-w-[1200px] p-6">
      <div className="mb-6 flex items-center justify-between gap-3">
        <div className="flex items-center gap-4">
          <h1 className="text-2xl font-bold">Vigila</h1>
          <nav className="flex items-center gap-1">
            <NavLink label="掃描" active={activeNav === "scans"} onClick={() => navigate("/")} />
            <NavLink
              label="引擎"
              active={activeNav === "engines"}
              onClick={() => navigate("/engines")}
            />
          </nav>
        </div>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => setCmdOpen(true)}
            className="text-muted-foreground"
          >
            <CommandIcon className="size-4" />
            ⌘K
          </Button>
          <ThemeToggle />
        </div>
      </div>

      {isEngines ? (
        <EnginesPage />
      ) : scanMatch ? (
        <ScanDetailPage
          scanId={scanMatch[1]}
          onBack={() => navigate("/")}
          onNavigateScan={(id) => navigate(`/scans/${id}`)}
        />
      ) : (
        <ScanListPage onOpen={(id) => navigate(`/scans/${id}`)} />
      )}

      <CommandPalette
        open={cmdOpen}
        onOpenChange={setCmdOpen}
        onNavigate={navigate}
        onTriggerScan={() => {
          navigate("/");
          /* 回到儀表板後聚焦掃描目標輸入框 讓使用者可直接輸入 */
          setTimeout(() => document.getElementById("scan-target-input")?.focus(), 50);
        }}
      />
    </div>
  );
}

/* NavLink 頂部導航連結 active 時高亮 */
function NavLink({
  label,
  active,
  onClick,
}: {
  label: string;
  active: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={
        "rounded-md px-3 py-1.5 text-sm font-medium transition-colors " +
        (active
          ? "bg-accent text-foreground"
          : "text-muted-foreground hover:text-foreground")
      }
    >
      {label}
    </button>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AppInner />
    </ThemeProvider>
  );
}
