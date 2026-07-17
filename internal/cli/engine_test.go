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
func (e *engineStub) TargetKinds() []scanner.TargetKind { return e.kinds }
func (e *engineStub) CheckInstalled() error             { return e.checkErr }
func (e *engineStub) ExitCodeIsFindings(code int) bool  { return false }
func (e *engineStub) Parse([]byte) ([]model.Finding, error) {
	return nil, nil
}
func (e *engineStub) BuildCommand(string, scanner.Options) (string, []string) {
	return e.name, nil
}
func (e *engineStub) Run(context.Context, string, scanner.Options) (*scanner.Result, error) {
	return &scanner.Result{}, nil
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
	if !rows[0].installed {
		t.Error("alpha checkErr 為 nil 應標記為已安裝")
	}
	if rows[1].installed {
		t.Error("mid checkErr 非 nil 應標記為未安裝")
	}
}

func TestRenderEngineRows(t *testing.T) {
	rows := []engineRow{
		{name: "semgrep", category: "SAST", kinds: "path", installed: true},
		{name: "nmap", category: "VA", kinds: "host", installed: false},
	}

	var out bytes.Buffer
	renderEngineRows(&out, rows)
	got := out.String()

	for _, want := range []string{"semgrep", "SAST", "path", "已安裝", "nmap", "VA", "host", "未安裝"} {
		if !strings.Contains(got, want) {
			t.Errorf("輸出應含 %q 實際:\n%s", want, got)
		}
	}
}

func TestRenderEngineRowsAligned(t *testing.T) {
	rows := []engineRow{
		{name: "trufflehog", category: "SECRET", kinds: "path", installed: true},
		{name: "nmap", category: "VA", kinds: "host", installed: false},
	}

	var out bytes.Buffer
	renderEngineRows(&out, rows)
	lines := strings.Split(strings.TrimRight(out.String(), "\n"), "\n")

	/* 每一列的「狀態」欄應在相同的顯示欄位起始 中文標題不得使欄位錯位 */
	var col int
	for i, line := range lines {
		idx := strings.Index(line, "狀")
		if i == 0 {
			col = displayWidth(line[:idx])
			continue
		}
		var mark string
		if strings.Contains(line, "已安裝") {
			mark = "已安裝"
		} else {
			mark = "未安裝"
		}
		at := displayWidth(line[:strings.Index(line, mark)])
		if at != col {
			t.Errorf("第 %d 列狀態欄起始於顯示欄位 %d 標題在 %d 未對齊\n%s", i, at, col, out.String())
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
