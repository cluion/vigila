package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
	"github.com/cluion/vigila/internal/store"
	"github.com/cluion/vigila/internal/store/sqlc"
)

/*
	NewScanCmd 建立 scan 子命令

支援三種模式

	--engine <name>   單一引擎
	--engine all      全部已註冊引擎
	--profile <name>  預定義流程 引擎組合與順序
*/
func NewScanCmd() *cobra.Command {
	var engineName string
	var profileName string

	cmd := &cobra.Command{
		Use:   "scan <path>",
		Short: "執行資安掃描",
		Long: `執行單一或多引擎掃描 結果寫入資料庫 可由 vigila serve 檢視

掃描模式
  --engine semgrep      單一引擎
  --engine all          全部已註冊引擎
  --profile full        預定義流程

內建 profile
  sast-only     僅 SAST semgrep
  sca-only      僅 SCA trivy
  secret-only   僅 Secret gitleaks
  code-audit    SAST 加 Secret
  full          全引擎`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			ctx := context.Background()
			db, err := store.Open(ctx, store.Config{})
			if err != nil {
				return err
			}
			defer db.Close()

			orch := core.New(sqlc.New(db))
			out := cmd.OutOrStdout()

			/* profile 模式優先 */
			if profileName != "" {
				fmt.Fprintf(out, "正在以 profile %s 掃描 %s ...\n", profileName, target)
				result, err := orch.RunProfile(ctx, profileName, target, scanner.Options{})
				if err != nil {
					return fmt.Errorf("掃描失敗: %w", err)
				}
				printSummary(out, result)
				return nil
			}

			/* all 模式 執行全部已註冊引擎 */
			if engineName == "all" {
				fmt.Fprintf(out, "正在以全部引擎掃描 %s ...\n", target)
				result, err := orch.RunMultiple(ctx, scanner.All(), target, scanner.Options{})
				if err != nil {
					return fmt.Errorf("掃描失敗: %w", err)
				}
				printSummary(out, result)
				return nil
			}

			/* 單一引擎 */
			s, err := scanner.Get(engineName)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "正在以 %s 掃描 %s ...\n", engineName, target)
			result, err := orch.RunSingle(ctx, s, target, scanner.Options{})
			if err != nil {
				return fmt.Errorf("掃描失敗: %w", err)
			}
			printSummary(out, result)
			return nil
		},
	}

	cmd.Flags().StringVarP(&engineName, "engine", "e", "semgrep", "掃描引擎 semgrep trivy gitleaks all")
	cmd.Flags().StringVarP(&profileName, "profile", "p", "", "掃描流程 profile 名稱")
	return cmd
}

/* printSummary 印出掃描結果的嚴重度與引擎統計 */
func printSummary(out io.Writer, r *core.ScanResult) {
	fmt.Fprintf(out, "\n掃描完成 scan %s\n", r.ScanID)
	fmt.Fprintf(out, "  耗時: %dms\n", r.DurationMs)
	fmt.Fprintf(out, "  發現: %d 個\n", r.Total)

	if r.Total > 0 {
		fmt.Fprintf(out, "  嚴重度分布\n")
		fmt.Fprintf(out, "    CRITICAL: %d\n", r.BySeverity[model.SeverityCritical])
		fmt.Fprintf(out, "    HIGH:     %d\n", r.BySeverity[model.SeverityHigh])
		fmt.Fprintf(out, "    MEDIUM:   %d\n", r.BySeverity[model.SeverityMedium])
		fmt.Fprintf(out, "    LOW:      %d\n", r.BySeverity[model.SeverityLow])

		if len(r.ByEngine) > 1 {
			fmt.Fprintf(out, "  引擎分布\n")
			for engine, count := range r.ByEngine {
				fmt.Fprintf(out, "    %s: %d\n", engine, count)
			}
		}
	}
}
