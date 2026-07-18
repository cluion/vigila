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
	ResolveSource 判定引擎目前的來源 以 binary 名同時作 docker profile 名

適用引擎的 Name 與 Binary 相同的情形 多數引擎如此
*/
func ResolveSource(binary string) Source {
	return ResolveSourceFor(binary, binary)
}

/*
	ResolveSourceFor 判定引擎來源 engineName 用於 docker profile binary 用於 managed 與 PATH

優先序 managed > docker(已勾選 profile) > system > missing
docker 需在 COMPOSE_PROFILES 明確勾選才啟用 屬使用者明確選擇 故蓋過偶然在 PATH 的系統版
managed 為釘選版仍最高 docker 以 engineName 對應 compose 服務名 與 binary 可能不同 如 zap 的 zap.sh
*/
func ResolveSourceFor(engineName, binary string) Source {
	if managedPath(binary) != "" {
		return SourceManaged
	}
	if dockerEnabled(engineName) {
		return SourceDocker
	}
	if _, err := exec.LookPath(binary); err == nil {
		return SourceSystem
	}
	return SourceMissing
}
