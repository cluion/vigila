package core

import (
	"fmt"
	"os"
	"strings"

	"github.com/cluion/vigila/internal/scanner"
)

/* Profile 定義一套掃描流程 引擎組合與順序 */
type Profile struct {
	Name        string
	Description string
	Engines     []string // 引擎名稱順序
	FailFast    bool     // 某引擎失敗是否中斷
}

/* Resolve 將 profile 的引擎名稱解析為 Scanner 實例 */
func (p Profile) Resolve() ([]scanner.Scanner, error) {
	var out []scanner.Scanner
	for _, name := range p.Engines {
		s, err := scanner.Get(name)
		if err != nil {
			return nil, fmt.Errorf("profile %s 引擎 %s 不可用: %w", p.Name, name, err)
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("profile %s 未定義任何引擎", p.Name)
	}
	return out, nil
}

/* builtinProfiles 為內建的掃描流程 */
var builtinProfiles = map[string]Profile{
	"sast-only": {
		Name:        "sast-only",
		Description: "僅原碼掃描 SAST",
		Engines:     []string{"semgrep"},
		FailFast:    false,
	},
	"sca-only": {
		Name:        "sca-only",
		Description: "僅依賴與容器掃描 SCA",
		Engines:     []string{"trivy"},
		FailFast:    false,
	},
	"secret-only": {
		Name:        "secret-only",
		Description: "僅密鑰掃描",
		Engines:     []string{"gitleaks"},
		FailFast:    false,
	},
	"code-audit": {
		Name:        "code-audit",
		Description: "程式碼資安完整審計 SAST 加 Secret",
		Engines:     []string{"semgrep", "gitleaks"},
		FailFast:    false,
	},
	"full": {
		Name:        "full",
		Description: "全引擎完整掃描 SAST SCA Secret",
		Engines:     []string{"semgrep", "trivy", "gitleaks"},
		FailFast:    false,
	},
	"dast-only": {
		Name:        "dast-only",
		Description: "網頁應用動態掃描 DAST target 為 URL",
		Engines:     []string{"nuclei"},
		FailFast:    false,
	},
	"web-deep": {
		Name:        "web-deep",
		Description: "網頁深度掃描 全 DAST 引擎 target 為 URL 較耗時",
		/* 由輕到重 nuclei template 快 nikto 掃 header sqlmap 探注入 zap 主被動最重 */
		Engines:  []string{"nuclei", "nikto", "sqlmap", "zap"},
		FailFast: false,
	},
	"va-only": {
		Name:        "va-only",
		Description: "網路服務弱點評估 VA target 為 host 或 IP",
		Engines:     []string{"nmap"},
		FailFast:    false,
	},
	"va-deep": {
		Name:        "va-deep",
		Description: "網路深度弱點評估 nmap 服務盤點加 openvas 完整掃描 target 為 host 需先起 openvas 容器",
		/* nmap 先快速盤點開放服務 openvas 再做完整弱點掃描（需 docker 容器已 up 且 feed 同步完） */
		Engines:  []string{"nmap", "openvas"},
		FailFast: false,
	},
}

/* GetProfile 依名稱取得 profile 先查內建 再查檔案 */
func GetProfile(name string) (Profile, error) {
	if p, ok := builtinProfiles[name]; ok {
		return p, nil
	}

	/* 嘗試讀取外部 profile 檔 <name>.profile.yaml 或 ~/.vigila/profiles/<name>.yaml */
	if p, err := loadProfileFromFile(name); err == nil {
		return p, nil
	}

	return Profile{}, fmt.Errorf("找不到 profile %s 可用 %s", name, ProfileNames())
}

/* ProfileNames 回傳內建 profile 名稱 排序 */
func ProfileNames() string {
	names := make([]string, 0, len(builtinProfiles))
	for n := range builtinProfiles {
		names = append(names, n)
	}
	return strings.Join(names, ", ")
}

/*
	loadProfileFromFile 從檔案載入簡易 profile 格式

檔案格式為簡單文字 每行一個引擎名 或含 description: 與 engines: 前綴
*/
func loadProfileFromFile(name string) (Profile, error) {
	candidates := []string{
		name + ".profile",
		name + ".yaml",
	}
	home, _ := os.UserHomeDir()
	if home != "" {
		candidates = append(candidates,
			home+"/.vigila/profiles/"+name+".yaml",
			home+"/.vigila/profiles/"+name+".profile",
		)
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		return parseSimpleProfile(name, string(data)), nil
	}

	return Profile{}, fmt.Errorf("profile 檔案不存在")
}

/*
	parseSimpleProfile 解析簡易 profile 格式

支援兩種格式

	一 每行一個引擎名 純文字
	二 YAML 子集 含 name description engines fail_fast
*/
func parseSimpleProfile(name, content string) Profile {
	p := Profile{Name: name, FailFast: false}
	var engines []string
	inEngines := false

	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		/* key: value 形式 */
		if idx := strings.Index(line, ":"); idx > 0 && !strings.HasPrefix(line, "-") {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])

			switch key {
			case "name":
				p.Name = val
			case "description":
				p.Description = val
			case "engines":
				inEngines = true
				if val != "" {
					/* 單行 engines: a, b, c 形式 */
					for _, e := range strings.Split(val, ",") {
						e = strings.TrimSpace(e)
						if e != "" {
							engines = append(engines, e)
						}
					}
					inEngines = false
				}
			case "fail_fast":
				p.FailFast = val == "true"
				inEngines = false
			default:
				inEngines = false
			}
			continue
		}

		/* engines 區塊下的列表項 */
		if inEngines || strings.HasPrefix(line, "-") {
			e := strings.TrimPrefix(line, "-")
			e = strings.TrimSpace(e)
			if e != "" {
				engines = append(engines, e)
			}
		}
	}

	/* 若沒有解析出 engines 但內容是純文字行 直接當引擎名 */
	if len(engines) == 0 {
		for _, line := range strings.Split(content, "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") && !strings.Contains(line, ":") {
				engines = append(engines, line)
			}
		}
	}

	p.Engines = engines
	return p
}
