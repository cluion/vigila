// Package scanner 為掃描引擎的 Adapter 層
//
// 每個引擎實作 Scanner 介面 新增引擎只需加一個 adapter 檔案
package scanner

import (
	"context"

	"github.com/cluion/vigila/internal/core/model"
)

/* InstallHint 引導使用者安裝引擎 供面板顯示 */
type InstallHint struct {
	DocsURL string // 官方安裝文件連結
	Command string // 一行最通用的安裝指令
}

/* Options 傳給 Scanner 的掃描選項 */
type Options struct {
	Config    string   // 規則集設定
	Severity  []string // 過濾的 severity
	Exclude   []string // 排除的路徑或 glob 各 adapter 轉為自身旗標 不支援者略過
	ExtraArgs []string // 額外 CLI 參數
}

/*
	ExcludeArgs 把排除清單組成引擎旗標 每個 pattern 一組 flag value

各引擎排除旗標不同 semgrep --exclude trivy --skip-dirs grype --exclude 等 傳入對應 flag 即可
*/
func ExcludeArgs(flag string, patterns []string) []string {
	out := make([]string, 0, len(patterns)*2)
	for _, p := range patterns {
		out = append(out, flag, p)
	}
	return out
}

/* Result 引擎執行的原始結果 含 stdout 供 Parse 與證據鏈 */
type Result struct {
	RawOutput  []byte // 引擎 stdout 或 report 檔內容
	ExitCode   int
	DurationMs int64
	Command    string // 實際執行的指令
}

/* Scanner 每個掃描引擎都要實作的統一介面 */
type Scanner interface {
	Name() string
	Category() model.Category
	Binary() string
	VersionArgs() []string // 取版本的 CLI 參數 各引擎不同
	TargetKinds() []TargetKind
	InstallHint() InstallHint
	CheckInstalled() error
	BuildCommand(target string, opts Options) (binary string, args []string)
	Run(ctx context.Context, target string, opts Options) (*Result, error)
	Parse(raw []byte) ([]model.Finding, error)
	ExitCodeIsFindings(code int) bool
}
