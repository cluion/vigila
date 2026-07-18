package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/sbom"
	"github.com/cluion/vigila/internal/store"
	"github.com/cluion/vigila/internal/store/sqlc"
)

/*
	NewSBOMCmd 建立 sbom 命令群組

sbom <target>       只產 SBOM 不跑漏洞引擎 建立一筆 scan 存為 artifact
sbom export <id>    把掃描已產生的 SBOM 匯出成檔案 供 CI 上傳或給下游工具
帶目標時直接產生 不帶引數時顯示說明 export 為子命令優先解析
*/
func NewSBOMCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "sbom [target]",
		Short: "軟體物料清單 SBOM 產生與管理",
		Long: `不需漏洞掃描 只產生軟體物料清單 SBOM

  vigila sbom ./myapp            只產 SBOM 不跑漏洞引擎
  vigila sbom export <scan-id>   匯出掃描的 SBOM

SBOM 以 syft 產 CycloneDX JSON 存為 scan artifact 僅支援本機路徑目標`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return cmd.Help()
			}

			target := args[0]
			ctx := context.Background()
			db, err := store.Open(ctx, store.Config{})
			if err != nil {
				return err
			}
			defer db.Close()

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "正在為 %s 產生 SBOM ...\n", target)
			result, err := core.New(sqlc.New(db)).RunSBOMOnly(ctx, target)
			if err != nil {
				return fmt.Errorf("SBOM 產生失敗: %w", err)
			}
			fmt.Fprintf(out, "\nSBOM 完成 scan %s\n  套件: %d 個\n  匯出: vigila sbom export %s -o sbom.json\n",
				result.ScanID, result.SBOMPackages, result.ScanID)
			return nil
		},
	}
	cmd.AddCommand(newSBOMExportCmd())
	return cmd
}

/* newSBOMExportCmd 建立 sbom export 子命令 依 scan ID 匯出 SBOM */
func newSBOMExportCmd() *cobra.Command {
	var output string

	cmd := &cobra.Command{
		Use:   "export <scan-id>",
		Short: "匯出掃描的 SBOM",
		Long: `依 scan ID 匯出該次掃描產生的 SBOM CycloneDX JSON

SBOM 需先於掃描時以 vigila scan <target> --sbom 產生
不指定 -o 則印至 stdout 可接管線`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			db, err := store.Open(ctx, store.Config{})
			if err != nil {
				return err
			}
			defer db.Close()

			return exportSBOM(ctx, sqlc.New(db), args[0], output, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVarP(&output, "output", "o", "", "輸出檔案路徑 不指定則印 stdout")
	return cmd
}

/*
	exportSBOM 取出 scan 的 SBOM artifact 並輸出

抽為獨立函式便於測試 指定 output 寫檔 否則印至 out
掃描無 SBOM 時回明確錯誤引導使用者以 --sbom 產生
*/
func exportSBOM(ctx context.Context, q *sqlc.Queries, scanID, output string, out io.Writer) error {
	art, err := q.GetLatestSBOMByScan(ctx, scanID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("scan %s 沒有 SBOM 請先以 vigila scan <target> --sbom 產生", scanID)
		}
		return fmt.Errorf("查詢 SBOM 失敗: %w", err)
	}

	if output == "" {
		_, err := io.WriteString(out, art.Content)
		return err
	}

	if err := os.WriteFile(output, []byte(art.Content), 0o644); err != nil {
		return fmt.Errorf("寫入檔案失敗: %w", err)
	}

	count := ""
	if pkgs, perr := sbom.ParsePackages([]byte(art.Content)); perr == nil {
		count = fmt.Sprintf(" 共 %d 個套件", len(pkgs))
	}
	fmt.Fprintf(out, "SBOM 已匯出 %s（%s）%s\n", output, art.Format, count)
	return nil
}
