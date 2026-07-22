package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/cluion/vigila/internal/engine"
	"github.com/cluion/vigila/internal/scanner"
)

/*
	NewEngineCmd 建立 engine 子命令群組

engine list 檢視已註冊引擎的類別 可接受目標型態與安裝狀態
*/
func NewEngineCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "engine",
		Short: "檢視與管理掃描引擎",
	}
	cmd.AddCommand(newEngineListCmd())
	cmd.AddCommand(newEngineInstallCmd())
	return cmd
}

/* newEngineInstallCmd 建立 engine install 子命令 下載官方 binary 到 managed 目錄 */
func newEngineInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install <engine>[@<version>]",
		Short: "下載引擎官方 binary 到 managed 目錄",
		Long: `從官方 GitHub release 下載引擎 binary 經 checksum 驗證後
存入 ~/.vigila/engines/ 免污染系統 PATH

加 @<version> 釘選特定版本（如 gitleaks@8.30.1）並記錄於 engines.lock.json
之後不帶版本安裝會沿用釘選 加 @latest 抓最新版並解除釘選

支援 gitleaks grype trivy trufflehog nuclei osv-scanner
semgrep 與 nmap 請改用官方安裝方式 見 engine list 的安裝指引`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "正在下載 %s ...\n", name)

			res, err := engine.NewInstaller().Install(name)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "已安裝 %s %s\n  路徑: %s\n", res.Engine, res.Version, res.Path)
			if res.Pinned {
				fmt.Fprintf(out, "  版本: 已釘選 %s（install %s@latest 可解除）\n", res.Version, res.Engine)
			}
			if res.SignatureVerified {
				fmt.Fprintf(out, "  簽章: ✓ 已通過 cosign keyless 驗證\n")
			}
			if res.Warning != "" {
				fmt.Fprintf(out, "  ⚠ %s\n", res.Warning)
			}
			return nil
		},
	}
}

/* newEngineListCmd 建立 engine list 子命令 */
func newEngineListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "列出已註冊引擎與安裝狀態",
		Long:  "列出所有已註冊引擎的類別 可接受的目標型態 與本機是否已安裝",
		Args:  cobra.NoArgs,
		Run: func(cmd *cobra.Command, args []string) {
			rows := collectEngineRows(scanner.All())
			renderEngineRows(cmd.OutOrStdout(), rows)
		},
	}
}

/* engineRow 為 engine list 的一列 */
type engineRow struct {
	name     string
	category string
	kinds    string
	version  string
	source   scanner.Source
}

/*
	collectEngineRows 把引擎轉為顯示列 依名稱排序

來源以 managed 優先再查 PATH 判定 版本實際執行引擎版本指令取得
版本偵測會 spawn subprocess 故各引擎並行 避免逐一序列化累積延遲
*/
func collectEngineRows(engines []scanner.Scanner) []engineRow {
	rows := make([]engineRow, len(engines))
	var wg sync.WaitGroup
	for i, e := range engines {
		wg.Add(1)
		go func(i int, e scanner.Scanner) {
			defer wg.Done()
			source := scanner.ResolveSourceFor(e.Name(), e.Binary())
			rows[i] = engineRow{
				name:     e.Name(),
				category: string(e.Category()),
				kinds:    scanner.KindsOf(e),
				version:  scanner.DetectVersion(e, source),
				source:   source,
			}
		}(i, e)
	}
	wg.Wait()

	sort.Slice(rows, func(i, j int) bool { return rows[i].name < rows[j].name })
	return rows
}

/* sourceLabel 把來源列舉轉為中文顯示字串 */
func sourceLabel(s scanner.Source) string {
	switch s {
	case scanner.SourceSystem:
		return "本機系統"
	case scanner.SourceManaged:
		return "managed 下載"
	case scanner.SourceDocker:
		return "docker 容器"
	default:
		return "未安裝"
	}
}

/*
	renderEngineRows 以對齊表格印出引擎清單

依顯示寬度對齊 而非 rune 數 中文標題一字佔兩欄 tabwriter 會算錯導致錯位
*/
func renderEngineRows(out io.Writer, rows []engineRow) {
	header := []string{"引擎", "類別", "目標型態", "版本", "來源"}
	cells := [][]string{header}
	for _, r := range rows {
		version := r.version
		if version == "" {
			version = "—"
		}
		cells = append(cells, []string{r.name, r.category, r.kinds, version, sourceLabel(r.source)})
	}

	/* 逐欄取最大顯示寬度 最後一欄不需補尾 */
	widths := make([]int, len(header))
	for _, row := range cells {
		for i, c := range row {
			if w := displayWidth(c); w > widths[i] {
				widths[i] = w
			}
		}
	}

	const gap = 2
	for _, row := range cells {
		var b strings.Builder
		for i, c := range row {
			b.WriteString(c)
			if i < len(row)-1 {
				pad := widths[i] - displayWidth(c) + gap
				b.WriteString(strings.Repeat(" ", pad))
			}
		}
		fmt.Fprintln(out, b.String())
	}
}

/*
	displayWidth 回傳字串在終端機的顯示寬度

CJK 與全形字元佔兩欄 其餘佔一欄 供表格對齊使用
*/
func displayWidth(s string) int {
	w := 0
	for _, r := range s {
		if isWide(r) {
			w += 2
		} else {
			w++
		}
	}
	return w
}

/* isWide 判斷 rune 是否為雙欄寬字元 涵蓋常見 CJK 與全形區段 */
func isWide(r rune) bool {
	switch {
	case r >= 0x1100 && r <= 0x115F, // Hangul Jamo
		r >= 0x2E80 && r <= 0x303E,   // CJK 部首 標點
		r >= 0x3041 && r <= 0x33FF,   // 平假名 片假名 CJK 符號
		r >= 0x3400 && r <= 0x4DBF,   // CJK 擴充 A
		r >= 0x4E00 && r <= 0x9FFF,   // CJK 統一表意
		r >= 0xA000 && r <= 0xA4CF,   // 彝文
		r >= 0xAC00 && r <= 0xD7A3,   // 韓文音節
		r >= 0xF900 && r <= 0xFAFF,   // CJK 相容表意
		r >= 0xFF00 && r <= 0xFF60,   // 全形 ASCII
		r >= 0xFFE0 && r <= 0xFFE6,   // 全形符號
		r >= 0x20000 && r <= 0x3FFFD: // CJK 擴充 B 以上
		return true
	}
	return false
}
