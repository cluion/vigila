package api

import (
	"sort"

	"github.com/cluion/vigila/internal/scanner"
)

/* installHint 為引擎安裝指引的 JSON 形狀 */
type installHint struct {
	DocsURL string `json:"docs_url"`
	Command string `json:"command"`
}

/* engineInfo 為引擎面板的一項 含類別 可接受目標型態 安裝狀態與安裝指引 */
type engineInfo struct {
	Name        string      `json:"name"`
	Category    string      `json:"category"`
	TargetKinds []string    `json:"target_kinds"`
	Installed   bool        `json:"installed"`
	InstallHint installHint `json:"install_hint"`
}

/*
	engineInfos 把引擎轉為面板顯示項 依名稱排序

安裝狀態以 CheckInstalled 是否回錯判定 每次呼叫即時查 PATH
*/
func engineInfos(engines []scanner.Scanner) []engineInfo {
	infos := make([]engineInfo, 0, len(engines))
	for _, e := range engines {
		kinds := e.TargetKinds()
		ks := make([]string, 0, len(kinds))
		for _, k := range kinds {
			ks = append(ks, string(k))
		}
		hint := e.InstallHint()
		infos = append(infos, engineInfo{
			Name:        e.Name(),
			Category:    string(e.Category()),
			TargetKinds: ks,
			Installed:   e.CheckInstalled() == nil,
			InstallHint: installHint{DocsURL: hint.DocsURL, Command: hint.Command},
		})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos
}
