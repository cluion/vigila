package cli

import (
	"context"
	"fmt"
	"io"
	"strings"

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
	--engine all      全部適用此目標的引擎
	--profile <name>  預定義流程 引擎組合與順序

target 型態決定可用的引擎 路徑走 SAST SCA Secret
URL 走 DAST host 或 IP 走 VA 詳見 scanner.DetectTargetKind
*/
func NewScanCmd() *cobra.Command {
	var engineName string
	var profileName string
	var withSBOM bool
	var excludes []string

	cmd := &cobra.Command{
		Use:   "scan <target>",
		Short: "執行資安掃描",
		Long: `執行單一或多引擎掃描 結果寫入資料庫 可由 vigila serve 檢視

掃描模式
  --engine semgrep      單一引擎
  --engine all          全部適用此目標的引擎
  --profile full        預定義流程

目標型態決定可用的引擎
  路徑    ./myapp              SAST SCA Secret 引擎
  URL     https://example.com  DAST 引擎
  主機    scanme.nmap.org      VA 引擎

內建 profile
  sast-only     僅 SAST semgrep
  sca-only      僅 SCA trivy
  secret-only   僅 Secret gitleaks
  code-audit    SAST 加 Secret
  full          原始碼全類型 SAST SCA Secret
  dast-only     僅 DAST nuclei
  va-only       僅 VA nmap`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			target := args[0]

			ctx := context.Background()
			db, err := store.Open(ctx, store.Config{})
			if err != nil {
				return err
			}
			defer db.Close()

			orch := core.New(sqlc.New(db)).WithSBOM(withSBOM)
			out := cmd.OutOrStdout()
			opts := scanner.Options{Exclude: excludes}

			/* profile 模式優先 */
			if profileName != "" {
				fmt.Fprintf(out, "正在以 profile %s 掃描 %s ...\n", profileName, target)
				result, err := orch.RunProfile(ctx, profileName, target, opts)
				if err != nil {
					return fmt.Errorf("掃描失敗: %w", err)
				}
				printSummary(out, result)
				return nil
			}

			/* all 模式 執行全部適用此目標的引擎 */
			if engineName == "all" {
				scanners, err := scanner.AllForTarget(target)
				if err != nil {
					return err
				}
				fmt.Fprintf(out, "正在以 %s 掃描 %s ...\n", joinNames(scanners), target)
				result, err := orch.RunMultiple(ctx, scanners, target, opts)
				if err != nil {
					return fmt.Errorf("掃描失敗: %w", err)
				}
				printSummary(out, result)
				return nil
			}

			/* 單一引擎 */
			s, err := scanner.GetForTarget(engineName, target)
			if err != nil {
				return err
			}
			fmt.Fprintf(out, "正在以 %s 掃描 %s ...\n", engineName, target)
			result, err := orch.RunSingle(ctx, s, target, opts)
			if err != nil {
				return fmt.Errorf("掃描失敗: %w", err)
			}
			printSummary(out, result)
			return nil
		},
	}

	cmd.Flags().StringVarP(&engineName, "engine", "e", "semgrep",
		fmt.Sprintf("掃描引擎 %s 或 all", scanner.Names()))
	cmd.Flags().StringVarP(&profileName, "profile", "p", "", "掃描流程 profile 名稱")
	cmd.Flags().BoolVar(&withSBOM, "sbom", false, "掃描後順帶產生 SBOM 軟體物料清單 需 syft 僅路徑目標")
	cmd.Flags().StringArrayVar(&excludes, "exclude", nil, "排除路徑 可重複 如 --exclude node_modules --exclude vendor（支援 semgrep trivy checkov）")
	cmd.AddCommand(newScanDeleteCmd())
	return cmd
}

/*
	newScanDeleteCmd 建立 scan delete 子命令 刪除指定掃描

子表 findings artifacts 等 ON DELETE CASCADE 連帶清除 不存在的 id 回錯
*/
func newScanDeleteCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "delete <scan-id>",
		Short: "刪除掃描及其所有結果",
		Long:  "依 scan ID 刪除掃描 連帶清除該掃描的引擎執行紀錄 漏洞關聯與 SBOM artifact",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			ctx := context.Background()
			db, err := store.Open(ctx, store.Config{})
			if err != nil {
				return err
			}
			defer db.Close()

			q := sqlc.New(db)
			if _, err := q.GetScan(ctx, id); err != nil {
				return fmt.Errorf("找不到 scan %s: %w", id, err)
			}
			if err := q.DeleteScan(ctx, id); err != nil {
				return fmt.Errorf("刪除 scan 失敗: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "已刪除 scan %s\n", id)
			return nil
		},
	}
}

/* joinNames 組出引擎名稱清單供訊息顯示 */
func joinNames(scanners []scanner.Scanner) string {
	names := make([]string, 0, len(scanners))
	for _, s := range scanners {
		names = append(names, s.Name())
	}
	return strings.Join(names, " ")
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

	/* SBOM 產出狀態 產生失敗不影響 scan 成敗 僅提示 */
	if r.SBOMErr != nil {
		fmt.Fprintf(out, "  SBOM: 未產生 (%v)\n", r.SBOMErr)
	} else if r.SBOMPackages > 0 {
		fmt.Fprintf(out, "  SBOM: %d 個套件\n", r.SBOMPackages)
	}
}
