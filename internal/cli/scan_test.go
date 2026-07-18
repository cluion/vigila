package cli

import (
	"strings"
	"testing"

	"github.com/cluion/vigila/internal/scanner"

	/* 匿名 import 觸發 adapter 註冊 與 cmd/vigila/main.go 一致 */
	_ "github.com/cluion/vigila/internal/scanner/checkov"
	_ "github.com/cluion/vigila/internal/scanner/gitleaks"
	_ "github.com/cluion/vigila/internal/scanner/grype"
	_ "github.com/cluion/vigila/internal/scanner/nmap"
	_ "github.com/cluion/vigila/internal/scanner/nuclei"
	_ "github.com/cluion/vigila/internal/scanner/osvscanner"
	_ "github.com/cluion/vigila/internal/scanner/semgrep"
	_ "github.com/cluion/vigila/internal/scanner/trivy"
	_ "github.com/cluion/vigila/internal/scanner/trufflehog"
)

func TestRealAdaptersTargetKinds(t *testing.T) {
	t.Run("路徑目標不含 DAST 與 VA 引擎", func(t *testing.T) {
		got, err := scanner.AllForTarget("./myapp")
		if err != nil {
			t.Fatalf("預期成功 得到錯誤: %v", err)
		}

		names := engineNames(got)
		assertContains(t, names, "semgrep", "trivy", "gitleaks", "grype", "trufflehog")
		assertMissing(t, names, "nuclei", "nmap")
	})

	t.Run("URL 目標只含 DAST 引擎", func(t *testing.T) {
		got, err := scanner.AllForTarget("https://testphp.vulnweb.com")
		if err != nil {
			t.Fatalf("預期成功 得到錯誤: %v", err)
		}

		names := engineNames(got)
		assertContains(t, names, "nuclei")
		assertMissing(t, names, "semgrep", "trivy", "gitleaks", "nmap")
	})

	t.Run("host 目標只含 VA 引擎", func(t *testing.T) {
		got, err := scanner.AllForTarget("scanme.nmap.org")
		if err != nil {
			t.Fatalf("預期成功 得到錯誤: %v", err)
		}

		names := engineNames(got)
		assertContains(t, names, "nmap")
		assertMissing(t, names, "semgrep", "nuclei")
	})
}

func TestRealAdaptersRejectWrongTarget(t *testing.T) {
	t.Run("引擎與目標相容時回傳引擎", func(t *testing.T) {
		s, err := scanner.GetForTarget("nmap", "scanme.nmap.org")
		if err != nil {
			t.Fatalf("預期成功 得到錯誤: %v", err)
		}
		if s.Name() != "nmap" {
			t.Errorf("引擎 = %s 預期 nmap", s.Name())
		}
	})

	t.Run("引擎不吃該目標型態時報錯 且訊息說明原因", func(t *testing.T) {
		_, err := scanner.GetForTarget("nmap", "./myapp")
		if err == nil {
			t.Fatal("預期報錯 但成功了")
		}

		msg := err.Error()
		for _, want := range []string{"nmap", "./myapp", "path", "host"} {
			if !strings.Contains(msg, want) {
				t.Errorf("錯誤訊息應含 %q 實際為: %s", want, msg)
			}
		}
	})

	t.Run("URL 目標指定 SAST 引擎時報錯", func(t *testing.T) {
		if _, err := scanner.GetForTarget("semgrep", "https://example.com"); err == nil {
			t.Error("預期報錯 但成功了")
		}
	})

	t.Run("未知引擎維持原本的錯誤", func(t *testing.T) {
		if _, err := scanner.GetForTarget("nonexistent", "./myapp"); err == nil {
			t.Error("預期報錯 但成功了")
		}
	})
}

func engineNames(scanners []scanner.Scanner) []string {
	out := make([]string, 0, len(scanners))
	for _, s := range scanners {
		out = append(out, s.Name())
	}
	return out
}

func assertContains(t *testing.T, got []string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !contains(got, w) {
			t.Errorf("引擎清單應含 %s 實際為 %v", w, got)
		}
	}
}

func assertMissing(t *testing.T, got []string, unwanted ...string) {
	t.Helper()
	for _, u := range unwanted {
		if contains(got, u) {
			t.Errorf("引擎清單不應含 %s 實際為 %v", u, got)
		}
	}
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}
