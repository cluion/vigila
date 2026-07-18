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

/* engineInfo 為引擎面板的一項 含類別 目標型態 版本 來源與安裝指引 */
type engineInfo struct {
	Name        string      `json:"name"`
	Category    string      `json:"category"`
	TargetKinds []string    `json:"target_kinds"`
	Installed   bool        `json:"installed"`
	Version     string      `json:"version"` // 偵測到的版本 未安裝或抓不到為空字串
	Source      string      `json:"source"`  // system | managed | missing
	InstallHint installHint `json:"install_hint"`
}

/*
	engineInfos 把引擎轉為面板顯示項 依名稱排序

來源以 managed 優先再查 PATH 判定 版本實際執行引擎版本指令取得
未安裝的引擎不執行版本指令 每次呼叫即時偵測
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
		source := scanner.ResolveSource(e.Binary())
		infos = append(infos, engineInfo{
			Name:        e.Name(),
			Category:    string(e.Category()),
			TargetKinds: ks,
			Installed:   source != scanner.SourceMissing,
			Version:     scanner.DetectVersion(e),
			Source:      string(source),
			InstallHint: installHint{DocsURL: hint.DocsURL, Command: hint.Command},
		})
	}
	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos
}
