package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* engineStub 為 engine list 測試用的假引擎 可控制安裝檢查 */
type engineStub struct {
	name     string
	cat      model.Category
	kinds    []scanner.TargetKind
	checkErr error
}

func (e *engineStub) Name() string                      { return e.name }
func (e *engineStub) Category() model.Category          { return e.cat }
func (e *engineStub) Binary() string                    { return e.name }
func (e *engineStub) VersionArgs() []string             { return []string{"--version"} }
func (e *engineStub) TargetKinds() []scanner.TargetKind { return e.kinds }
func (e *engineStub) InstallHint() scanner.InstallHint {
	return scanner.InstallHint{DocsURL: "https://example.com", Command: "install " + e.name}
}
func (e *engineStub) CheckInstalled() error            { return e.checkErr }
func (e *engineStub) ExitCodeIsFindings(code int) bool { return false }
func (e *engineStub) Parse([]byte) ([]model.Finding, error) {
	return nil, nil
}
func (e *engineStub) BuildCommand(string, scanner.Options) (string, []string) {
	return e.name, nil
}
func (e *engineStub) Run(context.Context, string, scanner.Options) (*scanner.Result, error) {
	return &scanner.Result{}, nil
}

/*
	TestEveryAdapterHasInstallHint 每個真實 adapter 都必須提供安裝指引

面板要引導使用者安裝未裝的引擎 少填任何一個都會讓面板出現空白指引
本測試靠 blank import 觸發全部 adapter 註冊 見 scan_test.go
*/
func TestEveryAdapterHasInstallHint(t *testing.T) {
	for _, s := range scanner.All() {
		hint := s.InstallHint()
		if hint.DocsURL == "" {
			t.Errorf("引擎 %s 的 InstallHint.DocsURL 不可為空", s.Name())
		}
		if hint.Command == "" {
			t.Errorf("引擎 %s 的 InstallHint.Command 不可為空", s.Name())
		}
	}
}

func TestCollectEngineRowsSortedByName(t *testing.T) {
	engines := []scanner.Scanner{
		&engineStub{name: "zeta", cat: model.CategoryVA, kinds: []scanner.TargetKind{scanner.TargetHost}},
		&engineStub{name: "alpha", cat: model.CategorySAST, kinds: []scanner.TargetKind{scanner.TargetPath}, checkErr: nil},
		&engineStub{name: "mid", cat: model.CategoryDAST, kinds: []scanner.TargetKind{scanner.TargetURL}, checkErr: errNotInstalled},
	}

	rows := collectEngineRows(engines)

	if len(rows) != 3 {
		t.Fatalf("應有 3 筆 實際 %d", len(rows))
	}
	if rows[0].name != "alpha" || rows[1].name != "mid" || rows[2].name != "zeta" {
		t.Errorf("應依名稱排序 實際 %s %s %s", rows[0].name, rows[1].name, rows[2].name)
	}
	/* stub 的 binary 名不在 PATH 也不在 managed 目錄 來源應為 missing */
	for _, r := range rows {
		if r.source != scanner.SourceMissing {
			t.Errorf("引擎 %s 不在任何來源 應為 missing 實際 %q", r.name, r.source)
		}
	}
}

func TestRenderEngineRows(t *testing.T) {
	rows := []engineRow{
		{name: "semgrep", category: "SAST", kinds: "path", version: "1.85.0", source: scanner.SourceSystem},
		{name: "nmap", category: "VA", kinds: "host", version: "", source: scanner.SourceMissing},
	}

	var out bytes.Buffer
	renderEngineRows(&out, rows)
	got := out.String()

	/* nmap 未安裝 版本應以破折號呈現 且來源標為未安裝 */
	for _, want := range []string{"semgrep", "SAST", "path", "1.85.0", "本機系統", "nmap", "VA", "host", "—", "未安裝"} {
		if !strings.Contains(got, want) {
			t.Errorf("輸出應含 %q 實際:\n%s", want, got)
		}
	}
}

func TestRenderEngineRowsAligned(t *testing.T) {
	rows := []engineRow{
		{name: "trufflehog", category: "SECRET", kinds: "path", version: "3.95.9", source: scanner.SourceManaged},
		{name: "nmap", category: "VA", kinds: "host", version: "", source: scanner.SourceMissing},
	}

	var out bytes.Buffer
	renderEngineRows(&out, rows)
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")

	/* 每一列的「來源」欄應在相同的顯示欄位起始 中文標題不得使欄位錯位 */
	var col int
	for i, line := range lines {
		if i == 0 {
			col = displayWidth(line[:strings.Index(line, "來源")])
			continue
		}
		var mark string
		switch {
		case strings.Contains(line, "本機系統"):
			mark = "本機系統"
		case strings.Contains(line, "managed 下載"):
			mark = "managed 下載"
		default:
			mark = "未安裝"
		}
		at := displayWidth(line[:strings.Index(line, mark)])
		if at != col {
			t.Errorf("第 %d 列來源欄起始於顯示欄位 %d 標題在 %d 未對齊\n%s", i, at, col, out.String())
		}
	}
}

func TestDisplayWidth(t *testing.T) {
	tests := []struct {
		in   string
		want int
	}{
		{"abc", 3},
		{"引擎", 4},
		{"nmap 主機", 9},
		{"", 0},
	}
	for _, tt := range tests {
		if got := displayWidth(tt.in); got != tt.want {
			t.Errorf("displayWidth(%q) = %d 預期 %d", tt.in, got, tt.want)
		}
	}
}

/* errNotInstalled 供 stub 模擬未安裝 */
var errNotInstalled = &stubErr{}

type stubErr struct{}

func (*stubErr) Error() string { return "未安裝" }
