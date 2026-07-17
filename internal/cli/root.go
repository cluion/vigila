package cli

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
)

// NewRootCmd 建立根命令 所有子命令掛在此處
func NewRootCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vigila",
		Short: "Vigila 開源資安掃描編排平台",
		Long: `Vigila 拉丁文「我監視 守護」 開源資安掃描編排平台

單一 Go binary 同時是 CLI 工具與 Web 平台 整合 SAST / SCA / Secret 等掃描引擎
支援單一掃描或一套流程 profile 編排 最後產出標準化報告

CLI 掃描的結果會寫入同一個資料庫 打開網頁即可檢視

快速開始
  vigila scan <path> --engine semgrep   掃描
  vigila serve                          啟動本機網頁 http://localhost:7780
  vigila engine list                    檢視可用引擎狀態

完整文件 https://vigila.dev
`,
		SilenceUsage:  true,
		SilenceErrors: true, /* 錯誤由 execute 統一印出 見該處說明 */
	}

	cmd.AddCommand(NewVersionCmd())
	cmd.AddCommand(NewScanCmd())
	cmd.AddCommand(NewServeCmd())
	cmd.AddCommand(NewReportCmd())
	cmd.AddCommand(NewDiffCmd())

	return cmd
}

// Execute 解析參數並執行對應命令
func Execute() {
	os.Exit(execute(NewRootCmd(), os.Stderr))
}

/*
	execute 執行命令並回傳 exit code 錯誤印到 stderr

與 Execute 分開是為了可測 Execute 呼叫 os.Exit 無法在測試中攔截
錯誤訊息由這裡統一印出 cobra 端以 SilenceErrors 關閉自己的輸出 避免印兩次
*/
func execute(cmd *cobra.Command, stderr io.Writer) int {
	cmd.SetErr(stderr)
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(stderr, "錯誤: %v\n", err)
		return 1
	}
	return 0
}
