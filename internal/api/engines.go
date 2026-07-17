package api

import (
	"sort"

	"github.com/cluion/vigila/internal/scanner"
)

/* engineInfo 為引擎面板的一項 含類別 可接受目標型態與安裝狀態 */
type engineInfo struct {
	Name        string   `json:"name"`
	Category    string   `json:"category"`
	TargetKinds []string `json:"target_kinds"`
	Installed   bool     `json:"installed"`
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
		infos = append(infos, engineInfo{
			Name:        e.Name(),
			Category:    string(e.Category()),
			TargetKinds: ks,
			Installed:   e.CheckInstalled() == nil,
		})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos
}
