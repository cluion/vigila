package cli

import (
	"context"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"time"

	"github.com/spf13/cobra"

	"github.com/cluion/vigila/internal/api"
	"github.com/cluion/vigila/internal/store"
	"github.com/cluion/vigila/internal/store/sqlc"
	"github.com/cluion/vigila/web"
)

/* NewServeCmd 建立 serve 子命令 啟動本機網頁伺服器 */
func NewServeCmd() *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "啟動網頁伺服器",
		Long:  "啟動本機網頁伺服器 檢視掃描結果 預設 http://localhost:7780",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()
			db, err := store.Open(ctx, store.Config{})
			if err != nil {
				return err
			}
			defer db.Close()

			/* 啟動時回收前一個 process 遺留的 running 殘留掃描 Ctrl-C 或被 kill 未能收尾者 */
			if n, err := sqlc.New(db).ReapStaleRunningScans(ctx); err != nil {
				log.Printf("回收殘留掃描失敗: %v", err)
			} else if n > 0 {
				log.Printf("已回收 %d 筆逾時未收尾的 running 掃描 標記為 failed", n)
			}

			srv := api.New(db)

			/* 嵌入前端 SPA 靜態檔 */
			distFS, err := fs.Sub(web.Dist, "dist")
			if err != nil {
				return fmt.Errorf("載入前端靜態檔失敗: %w", err)
			}
			srv.MountSPA(distFS)

			httpServer := &http.Server{
				Addr:              addr,
				Handler:           srv.Handler(),
				ReadHeaderTimeout: 5 * time.Second,
			}

			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Vigila 網頁伺服器啟動於 http://%s\n", addr)
			fmt.Fprintf(out, "按 Ctrl+C 停止\n")

			return httpServer.ListenAndServe()
		},
	}

	cmd.Flags().StringVarP(&addr, "addr", "a", "localhost:7780", "監聽位址")
	return cmd
}
