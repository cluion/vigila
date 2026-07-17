package scanner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
)

/* fakeScanner 為測試用的最小 Scanner 實作 */
type fakeScanner struct {
	name  string
	cat   model.Category
	kinds []TargetKind
}

func (f *fakeScanner) Name() string             { return f.name }
func (f *fakeScanner) Category() model.Category { return f.cat }
func (f *fakeScanner) Binary() string           { return f.name }
func (f *fakeScanner) CheckInstalled() error    { return nil }
func (f *fakeScanner) TargetKinds() []TargetKind {
	return f.kinds
}
func (f *fakeScanner) BuildCommand(string, Options) (string, []string) { return f.name, nil }
func (f *fakeScanner) Run(context.Context, string, Options) (*Result, error) {
	return &Result{}, nil
}
func (f *fakeScanner) Parse([]byte) ([]model.Finding, error) { return nil, nil }
func (f *fakeScanner) ExitCodeIsFindings(int) bool           { return false }

func TestDetectTargetKind(t *testing.T) {
	/* 建立真實目錄與檔案 驗證存在的路徑一律判為 path */
	dir := t.TempDir()
	nested := filepath.Join(dir, "myapp")
	if err := writeDir(nested); err != nil {
		t.Fatalf("建立測試目錄失敗: %v", err)
	}

	tests := []struct {
		name   string
		target string
		want   TargetKind
	}{
		{"http URL", "http://testphp.vulnweb.com", TargetURL},
		{"https URL 含路徑", "https://example.com/login?a=1", TargetURL},
		{"絕對路徑", dir, TargetPath},
		{"存在的子目錄", nested, TargetPath},
		{"相對路徑", "./myapp", TargetPath},
		{"當前目錄", ".", TargetPath},
		{"上層路徑", "../vigila", TargetPath},
		{"IPv4", "192.168.1.10", TargetHost},
		{"IPv6", "::1", TargetHost},
		{"host 含 port", "scanme.nmap.org:8080", TargetHost},
		{"IP 含 port", "10.0.0.1:443", TargetHost},
		{"網域名稱", "scanme.nmap.org", TargetHost},
		{"localhost", "localhost", TargetHost},
		{"localhost 含 port", "localhost:8080", TargetHost},
		{"不存在的裸目錄名視為路徑", "myapp", TargetPath},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectTargetKind(tt.target)
			if got != tt.want {
				t.Errorf("DetectTargetKind(%q) = %q 預期 %q", tt.target, got, tt.want)
			}
		})
	}
}

func TestAccepts(t *testing.T) {
	nmapLike := &fakeScanner{name: "nmap-like", cat: model.CategoryVA, kinds: []TargetKind{TargetHost}}
	trivyLike := &fakeScanner{name: "trivy-like", cat: model.CategorySCA, kinds: []TargetKind{TargetPath}}

	if !Accepts(nmapLike, TargetHost) {
		t.Error("nmap-like 應接受 host 目標")
	}
	if Accepts(nmapLike, TargetPath) {
		t.Error("nmap-like 不應接受 path 目標")
	}
	if !Accepts(trivyLike, TargetPath) {
		t.Error("trivy-like 應接受 path 目標")
	}
	if Accepts(trivyLike, TargetURL) {
		t.Error("trivy-like 不應接受 url 目標")
	}
}

func TestForTarget(t *testing.T) {
	restore := swapRegistry(map[string]Scanner{
		"zeta-sast": &fakeScanner{name: "zeta-sast", cat: model.CategorySAST, kinds: []TargetKind{TargetPath}},
		"alpha-sca": &fakeScanner{name: "alpha-sca", cat: model.CategorySCA, kinds: []TargetKind{TargetPath}},
		"dast-one":  &fakeScanner{name: "dast-one", cat: model.CategoryDAST, kinds: []TargetKind{TargetURL}},
		"va-one":    &fakeScanner{name: "va-one", cat: model.CategoryVA, kinds: []TargetKind{TargetHost}},
	})
	defer restore()

	t.Run("路徑目標只回傳吃 path 的引擎 並依名稱排序", func(t *testing.T) {
		got := names(ForTarget("./myapp"))
		want := []string{"alpha-sca", "zeta-sast"}
		assertEqual(t, got, want)
	})

	t.Run("URL 目標只回傳 DAST 引擎", func(t *testing.T) {
		got := names(ForTarget("https://example.com"))
		want := []string{"dast-one"}
		assertEqual(t, got, want)
	})

	t.Run("host 目標只回傳 VA 引擎", func(t *testing.T) {
		got := names(ForTarget("scanme.nmap.org"))
		want := []string{"va-one"}
		assertEqual(t, got, want)
	})
}

/* writeDir 建立測試目錄 */
func writeDir(path string) error { return os.MkdirAll(path, 0o755) }

/* swapRegistry 暫時替換全域 registry 回傳還原函式 */
func swapRegistry(fake map[string]Scanner) func() {
	registryMu.Lock()
	old := registry
	registry = fake
	registryMu.Unlock()

	return func() {
		registryMu.Lock()
		registry = old
		registryMu.Unlock()
	}
}

func TestAllForTarget(t *testing.T) {
	restore := swapRegistry(map[string]Scanner{
		"path-one": &fakeScanner{name: "path-one", cat: model.CategorySAST, kinds: []TargetKind{TargetPath}},
	})
	defer restore()

	t.Run("有適用引擎時回傳清單", func(t *testing.T) {
		got, err := AllForTarget("./myapp")
		if err != nil {
			t.Fatalf("預期成功 得到錯誤: %v", err)
		}
		assertEqual(t, names(got), []string{"path-one"})
	})

	t.Run("沒有引擎支援此目標時報錯", func(t *testing.T) {
		_, err := AllForTarget("https://example.com")
		if err == nil {
			t.Fatal("預期報錯 但成功了")
		}
		if !strings.Contains(err.Error(), "url") {
			t.Errorf("錯誤訊息應說明目標判定型態 實際為: %s", err)
		}
	})
}

func TestGetForTarget(t *testing.T) {
	restore := swapRegistry(map[string]Scanner{
		"host-one": &fakeScanner{name: "host-one", cat: model.CategoryVA, kinds: []TargetKind{TargetHost}},
	})
	defer restore()

	t.Run("引擎與目標相容時回傳引擎", func(t *testing.T) {
		s, err := GetForTarget("host-one", "scanme.nmap.org")
		if err != nil {
			t.Fatalf("預期成功 得到錯誤: %v", err)
		}
		if s.Name() != "host-one" {
			t.Errorf("引擎 = %s 預期 host-one", s.Name())
		}
	})

	t.Run("型態不符時報錯 訊息含引擎名 目標 判定型態 與可接受型態", func(t *testing.T) {
		_, err := GetForTarget("host-one", "./myapp")
		if err == nil {
			t.Fatal("預期報錯 但成功了")
		}
		for _, want := range []string{"host-one", "./myapp", "path", "host"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("錯誤訊息應含 %q 實際為: %s", want, err)
			}
		}
	})

	t.Run("未知引擎維持原本的錯誤", func(t *testing.T) {
		if _, err := GetForTarget("nonexistent", "./myapp"); err == nil {
			t.Error("預期報錯 但成功了")
		}
	})
}

func names(scanners []Scanner) []string {
	out := make([]string, 0, len(scanners))
	for _, s := range scanners {
		out = append(out, s.Name())
	}
	return out
}

func assertEqual(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("引擎數量 = %v 預期 %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("引擎清單 = %v 預期 %v", got, want)
		}
	}
}
