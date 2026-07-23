package core

import (
	"context"
	"strings"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* stubScanner 為 profile 測試用最小引擎 只需 Name 供 Resolve 查註冊表 */
type stubScanner struct{ name string }

func (s *stubScanner) Name() string             { return s.name }
func (s *stubScanner) Category() model.Category { return model.CategoryDAST }
func (s *stubScanner) Binary() string           { return s.name }
func (s *stubScanner) VersionArgs() []string    { return nil }
func (s *stubScanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetURL}
}
func (s *stubScanner) InstallHint() scanner.InstallHint { return scanner.InstallHint{} }
func (s *stubScanner) CheckInstalled() error            { return nil }
func (s *stubScanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	return s.name, nil
}
func (s *stubScanner) Run(_ context.Context, _ string, _ scanner.Options) (*scanner.Result, error) {
	return &scanner.Result{}, nil
}
func (s *stubScanner) Parse(_ []byte) ([]model.Finding, error) { return nil, nil }
func (s *stubScanner) ExitCodeIsFindings(code int) bool        { return false }

/* TestWebDeepProfileEngines 確認 web-deep 為全 DAST 引擎且不 FailFast */
func TestWebDeepProfileEngines(t *testing.T) {
	p, ok := builtinProfiles["web-deep"]
	if !ok {
		t.Fatal("應內建 web-deep profile")
	}
	want := []string{"nuclei", "nikto", "sqlmap", "zap"}
	if len(p.Engines) != len(want) {
		t.Fatalf("web-deep 引擎數 = %d 預期 %d", len(p.Engines), len(want))
	}
	for i, e := range want {
		if p.Engines[i] != e {
			t.Errorf("web-deep 第 %d 個引擎 = %q 預期 %q", i, p.Engines[i], e)
		}
	}
	if p.FailFast {
		t.Error("web-deep 不應 FailFast 單一引擎失敗不該中斷其餘")
	}
}

/* TestProfileNamesIncludesWebDeep 確認 web-deep 出現在可用 profile 清單 */
func TestProfileNamesIncludesWebDeep(t *testing.T) {
	if !strings.Contains(ProfileNames(), "web-deep") {
		t.Errorf("ProfileNames 應含 web-deep 實際 %s", ProfileNames())
	}
}

/*
	TestBuiltinProfilesResolve 確保每個內建 profile 的引擎名都可解析

註冊各 profile 引用到的引擎為 stub 後逐一 Resolve 防 profile 引用到未註冊的引擎名
*/
func TestBuiltinProfilesResolve(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range builtinProfiles {
		for _, name := range p.Engines {
			if seen[name] {
				continue
			}
			seen[name] = true
			scanner.Register(&stubScanner{name: name})
		}
	}

	for name, p := range builtinProfiles {
		if _, err := p.Resolve(); err != nil {
			t.Errorf("profile %s 無法解析: %v", name, err)
		}
	}
}
