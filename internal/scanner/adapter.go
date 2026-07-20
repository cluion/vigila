// Package scanner 為掃描引擎的 Adapter 層
//
// 每個引擎實作 Scanner 介面 新增引擎只需加一個 adapter 檔案
package scanner

import (
	"context"
	"fmt"
	"strings"

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

各引擎排除旗標不同 semgrep --exclude trivy --skip-dirs 等 傳入對應 flag 即可
防禦性略過以 - 開頭的 pattern 避免被引擎當旗標解析（argv 走私）呼叫端應已先 ValidateExcludes
*/
func ExcludeArgs(flag string, patterns []string) []string {
	out := make([]string, 0, len(patterns)*2)
	for _, p := range patterns {
		if strings.HasPrefix(p, "-") {
			continue
		}
		out = append(out, flag, p)
	}
	return out
}

/*
	ValidateExcludes 檢查排除 pattern 合法性 供輸入邊界呼叫

拒絕以 - 開頭者 否則會被引擎誤判為旗標造成引數走私 空字串亦拒絕
*/
func ValidateExcludes(patterns []string) error {
	for _, p := range patterns {
		if p == "" {
			return fmt.Errorf("排除路徑不可為空")
		}
		if strings.HasPrefix(p, "-") {
			return fmt.Errorf("排除路徑不可以 - 開頭: %q", p)
		}
	}
	return nil
}

/*
	ValidateTarget 檢查掃描目標合法性 供輸入邊界呼叫

拒絕以 - 開頭者 否則會被引擎當成旗標解析造成引數走私
例如 --output=/x（trivy 任意檔寫入）--config=遠端（semgrep 載惡意規則）
與 ValidateExcludes 同源防護 target 與 exclude 走同一條 argv 信任等級相同
檔名確實以 - 開頭時 請用 ./-name 或絕對路徑表達
*/
func ValidateTarget(target string) error {
	if strings.TrimSpace(target) == "" {
		return fmt.Errorf("掃描目標不可為空")
	}
	if strings.HasPrefix(target, "-") {
		return fmt.Errorf("掃描目標不可以 - 開頭 避免被引擎誤判為旗標: %q", target)
	}
	return nil
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
