// Package cli 為 CLI 命令層
package cli

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"
)

// 版本資訊 由 build 時 ldflags 注入 見 Makefile 與 .goreleaser.yml
var (
	version   = "0.1.0-dev"
	commit    = "none"
	date      = "unknown"
	builtBy   = "local"
	goVersion = runtime.Version()
)

// NewVersionCmd 建立版本子命令
func NewVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "顯示 Vigila 版本資訊",
		Long:  "顯示 Vigila 的版本 commit 建置時間與 Go 版本",
		Run: func(cmd *cobra.Command, args []string) {
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "vigila version %s\n", version)
			fmt.Fprintf(out, "  commit:     %s\n", commit)
			fmt.Fprintf(out, "  built:      %s\n", date)
			fmt.Fprintf(out, "  built by:   %s\n", builtBy)
			fmt.Fprintf(out, "  go version: %s\n", goVersion)
			fmt.Fprintf(out, "  platform:   %s/%s\n", runtime.GOOS, runtime.GOARCH)
		},
	}
}
