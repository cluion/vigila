package scanner

import (
	"context"
	"os/exec"
	"regexp"
	"time"
)

/*
	versionRe 從引擎版本輸出抽出語意化版本

容許前綴 v 與兩段式版本 nmap 為 7.95 形式 其餘為三段式
擷取群組不含前綴 v
*/
var versionRe = regexp.MustCompile(`v?(\d+\.\d+(?:\.\d+)?)`)

/* parseVersion 從版本指令輸出擷取版本字串 找不到回空字串 */
func parseVersion(output string) string {
	m := versionRe.FindStringSubmatch(output)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

/* versioner 為 DetectVersion 所需的最小介面 Scanner 皆滿足 */
type versioner interface {
	Binary() string
	VersionArgs() []string
}

/*
	DetectVersion 執行引擎的版本指令並擷取版本

來源為 missing 時直接回空字串 不執行不存在的 binary
合併 stdout 與 stderr nuclei 等引擎把版本印在 stderr
執行失敗或無版本輸出一律回空字串 供面板顯示 —
*/
func DetectVersion(s versioner) string {
	binary := s.Binary()
	if ResolveSource(binary) == SourceMissing {
		return ""
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, ResolveBinary(binary), s.VersionArgs()...)
	out, _ := cmd.CombinedOutput() // 忽略 exit code 有些引擎版本指令非零仍印出版本
	return parseVersion(string(out))
}
