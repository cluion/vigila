package scanner

import "os/exec"

/*
	Source 引擎的來源 反映 Resolve 的偵測優先序

managed 優先於 system docker 留待 compose 整合後補上
*/
type Source string

const (
	SourceSystem  Source = "system"  // 本機 PATH 直接 exec
	SourceManaged Source = "managed" // ~/.vigila/engines/ 下載的 binary
	SourceMissing Source = "missing" // 三來源皆無
)

/*
	ResolveSource 判定引擎目前的來源

順序與 ResolveBinary 一致 managed 優先 再查 PATH 皆無回 missing
*/
func ResolveSource(binary string) Source {
	if managedPath(binary) != "" {
		return SourceManaged
	}
	if _, err := exec.LookPath(binary); err == nil {
		return SourceSystem
	}
	return SourceMissing
}
