package cli

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/cluion/vigila/internal/report"
	"github.com/cluion/vigila/internal/store"
	"github.com/cluion/vigila/internal/store/sqlc"
)

/* NewReportCmd 建立 report 子命令 匯出掃描報告 */
func NewReportCmd() *cobra.Command {
	var format string
	var output string

	cmd := &cobra.Command{
		Use:   "report <scan-id>",
		Short: "匯出掃描報告",
		Long:  "依 scan ID 匯出報告 支援格式 sarif json html\n\nsarif 可上傳 GitHub code scanning\njson 為完整結構化資料\nhtml 可直接用瀏覽器開啟",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			scanID := args[0]
			ctx := context.Background()

			db, err := store.Open(ctx, store.Config{})
			if err != nil {
				return err
			}
			defer db.Close()
			q := sqlc.New(db)

			/* 取得 scan */
			scan, err := q.GetScan(ctx, scanID)
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					return fmt.Errorf("scan %s 不存在", scanID)
				}
				return fmt.Errorf("查詢 scan 失敗: %w", err)
			}

			/* 取得 engine_runs 與 findings */
			runs, err := q.ListEngineRunsByScan(ctx, scanID)
			if err != nil {
				return fmt.Errorf("查詢 engine_runs 失敗: %w", err)
			}
			findings, err := q.ListFindingsByScan(ctx, scanID)
			if err != nil {
				return fmt.Errorf("查詢 findings 失敗: %w", err)
			}

			/* 依格式產生 */
			var content string
			switch format {
			case "sarif":
				content, err = report.GenerateSARIF(scan, runs, findings)
			case "json":
				content, err = report.GenerateJSON(scan, runs, findings)
			case "html":
				content, err = report.GenerateHTML(scan, runs, findings)
			default:
				return fmt.Errorf("不支援的格式 %s 支援 sarif json html", format)
			}
			if err != nil {
				return fmt.Errorf("產生報告失敗: %w", err)
			}

			/* 輸出 指定 -o 寫檔 否則印 stdout */
			out := cmd.OutOrStdout()
			if output != "" {
				/* 0o600 報告含漏洞明細 可能有密鑰片段 僅本人可讀 */
				if err := os.WriteFile(output, []byte(content), 0o600); err != nil {
					return fmt.Errorf("寫入檔案失敗: %w", err)
				}
				fmt.Fprintf(out, "報告已匯出 %s 共 %d 個漏洞\n", output, len(findings))
			} else {
				fmt.Fprint(out, content)
			}
			return nil
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "html", "報告格式 sarif json html")
	cmd.Flags().StringVarP(&output, "output", "o", "", "輸出檔案路徑 不指定則印 stdout")
	return cmd
}
