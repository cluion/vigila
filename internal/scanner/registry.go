package scanner

import (
	"fmt"
	"sort"
	"sync"
)

var (
	registryMu sync.RWMutex
	registry   = map[string]Scanner{}
)

/* Register 註冊一個引擎 adapter */
func Register(s Scanner) {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry[s.Name()] = s
}

/* Get 依名稱取得引擎 */
func Get(name string) (Scanner, error) {
	registryMu.RLock()
	defer registryMu.RUnlock()
	s, ok := registry[name]
	if !ok {
		return nil, fmt.Errorf("未知引擎 %s 可用引擎 %s", name, Names())
	}
	return s, nil
}

/* Names 回傳已註冊引擎名 排序 */
func Names() string {
	registryMu.RLock()
	defer registryMu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return join(names)
}

/* All 回傳所有已註冊引擎 */
func All() []Scanner {
	registryMu.RLock()
	defer registryMu.RUnlock()
	out := make([]Scanner, 0, len(registry))
	for _, s := range registry {
		out = append(out, s)
	}
	return out
}

func join(names []string) string {
	out := ""
	for i, n := range names {
		if i > 0 {
			out += ", "
		}
		out += n
	}
	return out
}
