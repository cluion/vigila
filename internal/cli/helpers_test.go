package cli

import (
	"testing"

	"github.com/cluion/vigila/internal/scanner"
)

func TestSourceLabel(t *testing.T) {
	cases := map[scanner.Source]string{
		scanner.SourceSystem:  "本機系統",
		scanner.SourceManaged: "managed 下載",
		scanner.SourceDocker:  "docker 容器",
		scanner.SourceMissing: "未安裝",
	}
	for src, want := range cases {
		if got := sourceLabel(src); got != want {
			t.Errorf("sourceLabel(%v) = %q 預期 %q", src, got, want)
		}
	}
}

/* TestCommandConstructors 各命令建構子回傳有效 cobra 命令 */
func TestCommandConstructors(t *testing.T) {
	cmds := map[string]string{
		"scan":   NewScanCmd().Use,
		"engine": NewEngineCmd().Use,
		"report": NewReportCmd().Use,
		"diff":   NewDiffCmd().Use,
		"sbom":   NewSBOMCmd().Use,
		"serve":  NewServeCmd().Use,
	}
	for name, use := range cmds {
		if use == "" {
			t.Errorf("%s 命令的 Use 不應為空", name)
		}
	}

	/* engine 應有 list 與 install 子命令 */
	sub := map[string]bool{}
	for _, c := range NewEngineCmd().Commands() {
		sub[c.Name()] = true
	}
	if !sub["list"] || !sub["install"] {
		t.Errorf("engine 應含 list 與 install 子命令 實際 %v", sub)
	}
}
