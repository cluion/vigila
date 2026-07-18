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
	SourceDocker  Source = "docker"  // 容器 docker compose run 已勾選 profile
	SourceMissing Source = "missing" // 皆無
)

/*
	ResolveSource 判定引擎目前的來源

優先序 managed > system > docker 皆無回 missing
managed 釘選版優先於系統版 docker 為本機都沒裝時的備援
*/
func ResolveSource(binary string) Source {
	if managedPath(binary) != "" {
		return SourceManaged
	}
	if _, err := exec.LookPath(binary); err == nil {
		return SourceSystem
	}
	if dockerEnabled(binary) {
		return SourceDocker
	}
	return SourceMissing
}
