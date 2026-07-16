package cli

import (
	"fmt"
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
		SilenceUsage: true,
	}

	cmd.AddCommand(NewVersionCmd())
	cmd.AddCommand(NewScanCmd())
	cmd.AddCommand(NewServeCmd())

	return cmd
}

// Execute 解析參數並執行對應命令
func Execute() {
	if err := NewRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
