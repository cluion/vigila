package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"

	"github.com/go-chi/chi/v5"

	"github.com/cluion/vigila/internal/engine"
	"github.com/cluion/vigila/internal/scanner"
)

/* installHint 為引擎安裝指引的 JSON 形狀 */
type installHint struct {
	DocsURL string `json:"docs_url"`
	Command string `json:"command"`
}

/* engineInfo 為引擎面板的一項 含類別 目標型態 版本 來源 安裝指引與 docker 勾選狀態 */
type engineInfo struct {
	Name          string      `json:"name"`
	Category      string      `json:"category"`
	TargetKinds   []string    `json:"target_kinds"`
	Installed     bool        `json:"installed"`
	Version       string      `json:"version"`        // 偵測到的版本 未安裝或抓不到為空字串
	Source        string      `json:"source"`         // system | managed | docker | missing
	DockerCapable bool        `json:"docker_capable"` // 是否可經 docker 執行 供面板顯示開關
	DockerEnabled bool        `json:"docker_enabled"` // 是否已勾選 docker profile
	Installable   bool        `json:"installable"`    // 是否可經面板一鍵安裝（managed binary 下載）
	InstallHint   installHint `json:"install_hint"`
}

/*
	engineInfos 把引擎轉為面板顯示項 依名稱排序

來源以 managed 優先再查 PATH 判定 版本實際執行引擎版本指令取得
版本偵測會 spawn subprocess 故各引擎並行 避免逐一序列化累積延遲
*/
func engineInfos(engines []scanner.Scanner) []engineInfo {
	infos := make([]engineInfo, len(engines))
	var wg sync.WaitGroup
	for i, e := range engines {
		wg.Add(1)
		go func(i int, e scanner.Scanner) {
			defer wg.Done()
			kinds := e.TargetKinds()
			ks := make([]string, 0, len(kinds))
			for _, k := range kinds {
				ks = append(ks, string(k))
			}
			hint := e.InstallHint()
			source := scanner.ResolveSourceFor(e.Name(), e.Binary())
			infos[i] = engineInfo{
				Name:          e.Name(),
				Category:      string(e.Category()),
				TargetKinds:   ks,
				Installed:     source != scanner.SourceMissing,
				Version:       scanner.DetectVersion(e, source),
				Source:        string(source),
				DockerCapable: scanner.DockerCapable(e.Name()),
				DockerEnabled: scanner.DockerProfileEnabled(e.Name()),
				Installable:   engine.IsInstallable(e.Name()),
				InstallHint:   installHint{DocsURL: hint.DocsURL, Command: hint.Command},
			}
		}(i, e)
	}
	wg.Wait()

	sort.Slice(infos, func(i, j int) bool { return infos[i].Name < infos[j].Name })
	return infos
}

/*
	setEngineDocker POST /api/engines/{name}/docker 勾選或取消引擎的 docker 執行

body {"enabled": bool} 改寫 .env 的 COMPOSE_PROFILES 僅 docker-capable 引擎可操作
勾選後該引擎掃描時改走容器 且明確選擇蓋過偶然在 PATH 的系統版
*/
func (s *Server) setEngineDocker(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	var body struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "無效的請求內容")
		return
	}

	if !scanner.DockerCapable(name) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("引擎 %s 不支援 docker 執行", name))
		return
	}

	if err := scanner.SetDockerProfile(name, body.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"name":           name,
		"docker_enabled": scanner.DockerProfileEnabled(name),
	})
}

/*
	installEngine POST /api/engines/{name}/install 一鍵安裝 managed binary

僅 installable 引擎可操作（gitleaks grype trivy trufflehog nuclei osv-scanner）
其餘回 400 引導使用者依安裝指引手動處理
同步執行 installer 下載 checksum 驗證 解壓 寫入 managed 目錄 完成後回版本與路徑
*/
func (s *Server) installEngine(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")

	if !engine.IsInstallable(name) {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("引擎 %s 不支援一鍵安裝 請參考安裝指引", name))
		return
	}

	res, err := engine.NewInstaller().Install(name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"engine":             res.Engine,
		"version":            res.Version,
		"path":               res.Path,
		"signature_verified": res.SignatureVerified,
		"warning":            res.Warning,
	})
}
