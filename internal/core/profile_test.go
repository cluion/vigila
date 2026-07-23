package core

import (
	"context"
	"os"
	"path/filepath"
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

/* TestVaDeepProfileEngines 確認 va-deep 為 nmap + openvas 且不 FailFast */
func TestVaDeepProfileEngines(t *testing.T) {
	p, ok := builtinProfiles["va-deep"]
	if !ok {
		t.Fatal("應內建 va-deep profile")
	}
	want := []string{"nmap", "openvas"}
	if len(p.Engines) != len(want) {
		t.Fatalf("va-deep 引擎數 = %d 預期 %d", len(p.Engines), len(want))
	}
	for i, e := range want {
		if p.Engines[i] != e {
			t.Errorf("va-deep 第 %d 個引擎 = %q 預期 %q", i, p.Engines[i], e)
		}
	}
	if p.FailFast {
		t.Error("va-deep 不應 FailFast")
	}
}

/* TestProfileNamesIncludesDeep 確認 web-deep 與 va-deep 出現在可用 profile 清單 */
func TestProfileNamesIncludesDeep(t *testing.T) {
	names := ProfileNames()
	for _, want := range []string{"web-deep", "va-deep"} {
		if !strings.Contains(names, want) {
			t.Errorf("ProfileNames 應含 %s 實際 %s", want, names)
		}
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

/* TestParseSimpleProfileFormats 涵蓋 YAML 子集與純文字兩種 profile 檔格式 */
func TestParseSimpleProfileFormats(t *testing.T) {
	t.Run("YAML 子集", func(t *testing.T) {
		p := parseSimpleProfile("custom", "name: my\ndescription: 測試\nengines:\n  - semgrep\n  - trivy\nfail_fast: true\n")
		if p.Name != "my" || p.Description != "測試" || !p.FailFast {
			t.Errorf("解析 meta 不符 %+v", p)
		}
		if len(p.Engines) != 2 || p.Engines[0] != "semgrep" || p.Engines[1] != "trivy" {
			t.Errorf("engines 不符 %v", p.Engines)
		}
	})

	t.Run("單行 engines 逗號分隔", func(t *testing.T) {
		p := parseSimpleProfile("c", "engines: semgrep, gitleaks\n")
		if len(p.Engines) != 2 {
			t.Errorf("單行 engines 應解出 2 個 實際 %v", p.Engines)
		}
	})

	t.Run("純文字每行一引擎", func(t *testing.T) {
		p := parseSimpleProfile("c", "# 註解\nsemgrep\ntrivy\n")
		if len(p.Engines) != 2 || p.Engines[0] != "semgrep" {
			t.Errorf("純文字格式不符 %v", p.Engines)
		}
	})
}

/* TestLoadProfileFromFile 從當前目錄的 <name>.profile 檔載入 */
func TestLoadProfileFromFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "web.profile"), []byte("nuclei\nzap\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	old, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })

	p, err := loadProfileFromFile("web")
	if err != nil {
		t.Fatalf("載入 profile 檔失敗: %v", err)
	}
	if len(p.Engines) != 2 || p.Engines[0] != "nuclei" {
		t.Errorf("載入的 engines 不符 %v", p.Engines)
	}

	if _, err := loadProfileFromFile("nonexistent"); err == nil {
		t.Error("不存在的 profile 檔應回錯")
	}
}

/* TestGetProfileBuiltinAndUnknown 內建取得成功 未知回錯 */
func TestGetProfileBuiltinAndUnknown(t *testing.T) {
	if _, err := GetProfile("full"); err != nil {
		t.Errorf("內建 full 應可取得: %v", err)
	}
	if _, err := GetProfile("no-such-profile-xyz"); err == nil {
		t.Error("未知 profile 應回錯")
	}
}
