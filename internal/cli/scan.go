package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
	"github.com/cluion/vigila/internal/store"
	"github.com/cluion/vigila/internal/store/sqlc"
)

/* NewScanCmd 建立 scan 子命令 */
func NewScanCmd() *cobra.Command {
	var engineName string

	cmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "執行資安掃描",
		Long:  "執行單一引擎掃描 結果寫入資料庫 可由 vigila serve 檢視",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			/* 取得引擎 */
			s, err := scanner.Get(engineName)
			if err != nil {
				return err
			}

			/* 開啟 DB */
			ctx := context.Background()
			db, err := store.Open(ctx, store.Config{})
			if err != nil {
				return err
			}
			defer db.Close()

			orch := core.New(sqlc.New(db))

			/* 執行掃描 */
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "正在以 %s 掃描 %s ...\n", engineName, target)

			result, err := orch.RunSingle(ctx, s, target, scanner.Options{})
			if err != nil {
				return fmt.Errorf("掃描失敗: %w", err)
			}

			/* 輸出結果摘要 */
			printSummary(out, result)
			return nil
		},
	}

	cmd.Flags().StringVarP(&engineName, "engine", "e", "semgrep", "掃描引擎 如 semgrep")
	return cmd
}

/* printSummary 印出掃描結果的嚴重度統計 */
func printSummary(out interface{ Write([]byte) (int, error) }, r *core.ScanResult) {
	fmt.Fprintf(out, "\n掃描完成 scan %s\n", r.ScanID)
	fmt.Fprintf(out, "  引擎:     %s\n", r.Engine)
	fmt.Fprintf(out, "  類別:     %s\n", r.Category)
	fmt.Fprintf(out, "  耗時:     %dms\n", r.DurationMs)
	fmt.Fprintf(out, "  發現:     %d 個\n", r.Total)
	if r.Total > 0 {
		fmt.Fprintf(out, "    CRITICAL: %d\n", r.BySeverity[model.SeverityCritical])
		fmt.Fprintf(out, "    HIGH:     %d\n", r.BySeverity[model.SeverityHigh])
		fmt.Fprintf(out, "    MEDIUM:   %d\n", r.BySeverity[model.SeverityMedium])
		fmt.Fprintf(out, "    LOW:      %d\n", r.BySeverity[model.SeverityLow])
	}
}
