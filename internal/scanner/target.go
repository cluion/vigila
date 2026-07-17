package scanner

import (
	"fmt"
	"net"
	"os"
	"sort"
	"strings"
)

/*
	TargetKind 標註掃描目標的型態

不同類別的引擎吃不同型態的目標 SAST 與 SCA 吃檔案路徑
DAST 吃 URL VA 吃主機或 IP 混用會導致引擎必然失敗
*/
type TargetKind string

const (
	TargetPath TargetKind = "path" // 本機檔案或目錄
	TargetURL  TargetKind = "url"  // 含 scheme 的完整網址
	TargetHost TargetKind = "host" // 主機名 IP 或 host:port
)

/*
	DetectTargetKind 從 target 字串推導目標型態

判斷順序為由強到弱的訊號

	一 含 scheme 視為 URL
	二 本機確實存在的路徑視為 path 這是最可靠的訊號
	三 可解析為 IP 或 localhost 視為 host
	四 含連接埠且不含路徑分隔的視為 host
	五 含點且不含路徑分隔的視為網域名
	六 其餘視為 path 讓引擎自己回報找不到目標

無點的內網主機名如 webserver01 與目錄名無法區分 會判為 path
這類目標請加連接埠 webserver01:80 或用 URL 形式明確表達
*/
func DetectTargetKind(target string) TargetKind {
	if strings.Contains(target, "://") {
		return TargetURL
	}

	/* 本機存在的路徑優先 目錄名長得像網域時仍應視為路徑 */
	if _, err := os.Stat(target); err == nil {
		return TargetPath
	}

	if net.ParseIP(target) != nil {
		return TargetHost
	}

	/* localhost 沒有點 靠下面的網域規則抓不到 但它是掃描本機服務最常見的目標 */
	if strings.EqualFold(target, "localhost") {
		return TargetHost
	}

	hasSeparator := strings.ContainsAny(target, "/\\")

	/* host:port 形式 如 scanme.nmap.org:8080 或 10.0.0.1:443 */
	if strings.Contains(target, ":") && !hasSeparator {
		return TargetHost
	}

	/* 網域名 如 scanme.nmap.org */
	if strings.Contains(target, ".") && !hasSeparator && !strings.HasPrefix(target, ".") {
		return TargetHost
	}

	return TargetPath
}

/* Accepts 回報引擎是否接受該型態的目標 */
func Accepts(s Scanner, kind TargetKind) bool {
	for _, k := range s.TargetKinds() {
		if k == kind {
			return true
		}
	}
	return false
}

/* KindsOf 回傳引擎可接受的目標型態 供錯誤訊息使用 */
func KindsOf(s Scanner) string {
	kinds := s.TargetKinds()
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return strings.Join(out, ", ")
}

/*
	ForTarget 回傳可掃描該 target 的已註冊引擎 依名稱排序

排序確保同一目標每次的引擎執行順序一致 掃描結果可重現
*/
func ForTarget(target string) []Scanner {
	kind := DetectTargetKind(target)

	registryMu.RLock()
	defer registryMu.RUnlock()

	out := make([]Scanner, 0, len(registry))
	for _, s := range registry {
		if Accepts(s, kind) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name() < out[j].Name() })
	return out
}

/*
	AllForTarget 回傳適用此目標的引擎 一個都沒有時報錯

供 all 模式使用 CLI 與 Web API 共用同一份判斷與訊息
*/
func AllForTarget(target string) ([]Scanner, error) {
	scanners := ForTarget(target)
	if len(scanners) == 0 {
		return nil, fmt.Errorf("沒有引擎支援此目標\n  目標 %s 判定為 %s\n  已註冊引擎: %s",
			target, DetectTargetKind(target), Names())
	}
	return scanners, nil
}

/*
	GetForTarget 取得指定引擎 並確認它接受此目標型態

使用者明確指定了引擎 型態不符時直接報錯 不留下一筆註定失敗的 scan 紀錄
*/
func GetForTarget(name, target string) (Scanner, error) {
	s, err := Get(name)
	if err != nil {
		return nil, err
	}

	kind := DetectTargetKind(target)
	if !Accepts(s, kind) {
		return nil, fmt.Errorf("引擎 %s 不支援此目標\n  目標 %s 判定為 %s\n  %s 接受的目標型態: %s",
			name, target, kind, name, KindsOf(s))
	}
	return s, nil
}
