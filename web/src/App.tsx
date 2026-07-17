import { useState, useEffect } from "react";
import { useHashRoute } from "@/hooks/useHashRoute";
import { ThemeProvider } from "@/lib/theme";
import { ScanListPage } from "@/pages/ScanListPage";
import { ScanDetailPage } from "@/pages/ScanDetailPage";
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

  return (
    <div className="mx-auto max-w-[1200px] p-6">
      <div className="mb-6 flex items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <h1 className="text-2xl font-bold">Vigila</h1>
          <span className="text-[13px] text-muted-foreground">資安掃描編排平台</span>
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

      {scanMatch ? (
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
        onTriggerScan={() => navigate("/")}
      />
    </div>
  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AppInner />
    </ThemeProvider>
  );
}
