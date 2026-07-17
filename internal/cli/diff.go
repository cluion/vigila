package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/store"
	"github.com/cluion/vigila/internal/store/sqlc"
)

/* NewDiffCmd 建立 diff 子命令 比較兩次掃描的 findings 差異 */
func NewDiffCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "diff <scan-id-1> <scan-id-2>",
		Short: "比較兩次掃描的漏洞差異",
		Long: `比較兩次掃描的漏洞差異 以去重 hash 計算

  新增  第二次掃描才出現的漏洞
  消失  第一次有但第二次沒再出現的漏洞
  不變  兩次都存在的漏洞

兩次掃描需屬於同一個 project`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			db, err := store.Open(ctx, store.Config{})
			if err != nil {
				return err
			}
			defer db.Close()

			diff, err := core.Diff(ctx, sqlc.New(db), args[0], args[1])
			if err != nil {
				return err
			}

			printDiff(cmd.OutOrStdout(), diff)
			return nil
		},
	}
}

/* printDiff 印出差異摘要與明細 */
func printDiff(out io.Writer, d *core.DiffResult) {
	fmt.Fprintf(out, "掃描差異 %s → %s\n", d.From.ID, d.To.ID)
	fmt.Fprintf(out, "  新增: %d 個\n", len(d.Added))
	printDiffFindings(out, d.Added)
	fmt.Fprintf(out, "  消失: %d 個\n", len(d.Removed))
	printDiffFindings(out, d.Removed)
	fmt.Fprintf(out, "  不變: %d 個\n", d.Unchanged)
}

/* printDiffFindings 印出 findings 明細行 */
func printDiffFindings(out io.Writer, findings []sqlc.Finding) {
	for _, f := range findings {
		location := ""
		if f.FilePath != nil {
			location = *f.FilePath
			if f.StartLine != nil {
				location = fmt.Sprintf("%s:%d", location, *f.StartLine)
			}
		} else if f.Url != nil {
			location = *f.Url
		} else if f.Host != nil {
			location = *f.Host
			if f.Port != nil {
				location = fmt.Sprintf("%s:%s", location, *f.Port)
			}
		} else if f.PkgName != nil {
			location = *f.PkgName
			if f.InstalledVersion != nil {
				location = fmt.Sprintf("%s@%s", location, *f.InstalledVersion)
			}
		}
		fmt.Fprintf(out, "    [%s] %s  %s  %s\n", f.Severity, f.Engine, f.Title, location)
	}
}
