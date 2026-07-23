// Package nmap 為 Nmap VA 引擎 adapter
//
// Nmap 是網路服務偵測工具 target 為 host 或 IP 如 192.168.1.10
// 本 adapter 用 -sV 做服務版本偵測 --script vuln 跑 NSE 弱點腳本 -oX - 輸出 XML 到 stdout
// 每個 open port 產一筆服務 finding 另把 vuln 腳本結果轉為弱點 finding
// vulners 的結構化 CVE 表格逐一成 finding（severity 取 CVSS）其餘腳本每支一筆
//
// 授權 Nmap 為 GPL-2.0 Vigila 以 subprocess 呼叫不連結程式碼
// 與既有 TruffleHog AGPL 同為外部 binary 不影響 Vigila 的 MIT 授權
package nmap

import (
	"context"
	"encoding/xml"
	"fmt"
	"runtime"
	"strconv"
	"strings"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

const binaryName = "nmap"

/* Scanner 為 Nmap adapter 實作 */
type Scanner struct{}

func init() { scanner.Register(&Scanner{}) }

func (s *Scanner) Name() string             { return binaryName }
func (s *Scanner) Category() model.Category { return model.CategoryVA }
func (s *Scanner) Binary() string           { return binaryName }
func (s *Scanner) VersionArgs() []string    { return []string{"--version"} }

/* TargetKinds nmap 掃描網路主機 只吃 host IP 或 host:port */
func (s *Scanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetHost}
}

/*
	InstallHint nmap 安裝指引 依作業系統給對應套件管理器指令

nmap 無官方可攜 binary 也非 pip 套件 故依 GOOS 提示 macOS brew Linux apt Windows choco
*/
func (s *Scanner) InstallHint() scanner.InstallHint {
	cmd := "sudo apt install nmap"
	switch runtime.GOOS {
	case "darwin":
		cmd = "brew install nmap"
	case "windows":
		cmd = "choco install nmap"
	}
	return scanner.InstallHint{
		DocsURL: "https://nmap.org/download.html",
		Command: cmd,
	}
}

/* CheckInstalled 確認 nmap 已安裝 */
func (s *Scanner) CheckInstalled() error {
	return scanner.CheckBinary(binaryName)
}

/*
	BuildCommand 組 nmap 掃描指令

-sV 探測服務版本
--script vuln 跑 NSE vuln 類腳本 對服務比對已知漏洞與 CVE（較耗時 但升級為真弱點掃描）
-oX - 輸出 XML 到 stdout
*/
func (s *Scanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	args := []string{
		"-sV",
		"--script", "vuln",
		"-oX", "-",
	}
	args = append(args, opts.ExtraArgs...)
	args = append(args, target)
	return binaryName, args
}

/*
	Run 執行掃描 依來源分流 stdout 即 XML

docker 來源用官方 image 不掛載 直接把目標 host 傳入容器
容器 host 網路 network_mode host 由 compose service 承擔 掃得到內網主機
系統來源走本機 subprocess
*/
func (s *Scanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	binary, args := s.BuildCommand(target, opts)
	if scanner.ResolveSourceFor(s.Name(), binary) == scanner.SourceDocker {
		return scanner.DockerRunNoMount(ctx, s.Name(), args)
	}
	return scanner.DefaultRun(ctx, binary, args)
}

/* ExitCodeIsFindings nmap 預設 exit 0 不論有無 finding */
func (s *Scanner) ExitCodeIsFindings(code int) bool {
	return false
}

/* nmapOutput 為 nmap XML 輸出結構 只取需要的欄位 */
type nmapOutput struct {
	XMLName xml.Name   `xml:"nmaprun"`
	Hosts   []nmapHost `xml:"host"`
}

type nmapHost struct {
	Addresses []nmapAddress `xml:"address"`
	Hostnames nmapHostnames `xml:"hostnames"`
	Ports     nmapPorts     `xml:"ports"`
}

type nmapAddress struct {
	Addr   string `xml:"addr,attr"`
	Type   string `xml:"addrtype,attr"`
	Vendor string `xml:"vendor,attr"`
}

type nmapHostnames struct {
	Hostnames []nmapHostname `xml:"hostname"`
}

type nmapHostname struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type nmapPorts struct {
	Ports []nmapPort `xml:"port"`
}

type nmapPort struct {
	PortID  string       `xml:"portid,attr"`
	Proto   string       `xml:"protocol,attr"`
	State   nmapState    `xml:"state"`
	Service nmapService  `xml:"service"`
	Scripts []nmapScript `xml:"script"`
}

/* nmapScript 為一個 NSE 腳本結果 output 為純文字 tables 為結構化資料如 vulners 的 CVE 清單 */
type nmapScript struct {
	ID     string      `xml:"id,attr"`
	Output string      `xml:"output,attr"`
	Tables []nmapTable `xml:"table"`
}

/* nmapTable 為 NSE 腳本的巢狀結構化資料 vulners 以巢狀 table 列出每個 CVE */
type nmapTable struct {
	Key    string      `xml:"key,attr"`
	Elems  []nmapElem  `xml:"elem"`
	Tables []nmapTable `xml:"table"`
}

/* nmapElem 為 table 內的鍵值 如 id=CVE-2021-1234 cvss=7.5 */
type nmapElem struct {
	Key   string `xml:"key,attr"`
	Value string `xml:",chardata"`
}

type nmapState struct {
	State  string `xml:"state,attr"`
	Reason string `xml:"reason,attr"`
}

type nmapService struct {
	Name    string `xml:"name,attr"`
	Product string `xml:"product,attr"`
	Version string `xml:"version,attr"`
	Extra   string `xml:"extrainfo,attr"`
}

/*
	Parse 將 nmap XML 轉為統一 Finding

遍歷 host 與 port 只收 open 狀態的 port
每個 open port 產生一筆 finding 記錄服務與版本
有版本資訊標 MEDIUM 潛在風險 單純 open 標 LOW
套用 VA fingerprint engine + rule_id + host + port
*/
func (s *Scanner) Parse(raw []byte) ([]model.Finding, error) {
	if len(raw) == 0 {
		return []model.Finding{}, nil
	}

	var out nmapOutput
	if err := xml.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("nmap XML 解析失敗: %w", err)
	}

	findings := make([]model.Finding, 0)
	for _, h := range out.Hosts {
		host := hostLabel(h)
		if host == "" {
			continue
		}

		for _, p := range h.Ports.Ports {
			/* 只記錄 open 的 port */
			if p.State.State != "open" {
				continue
			}

			severity := model.SeverityLow
			snippet := buildServiceSnippet(p.Service)
			/* 有版本資訊視為潛在風險 升為 MEDIUM */
			if p.Service.Product != "" || p.Service.Version != "" {
				severity = model.SeverityMedium
			}

			f := model.Finding{
				Engine:           binaryName,
				Category:         model.CategoryVA,
				RuleID:           "nmap-service",
				Title:            fmt.Sprintf("開放服務 %s/%s", p.PortID, p.Proto),
				Description:      snippet,
				Severity:         severity,
				Host:             host,
				Port:             p.PortID,
				Snippet:          snippet,
				UniqueIDFromTool: host + ":" + p.PortID,
			}

			f.HashCode = core.Fingerprint(f)
			findings = append(findings, f)

			/* NSE vuln 腳本結果 每個 CVE 或每支腳本各成一筆弱點 finding */
			findings = append(findings, scriptFindings(host, p)...)
		}
	}

	return findings, nil
}

/* scriptSnippetMax 為 NSE 腳本輸出納入 finding 的長度上限 避免超長輸出灌爆描述 */
const scriptSnippetMax = 2000

/*
	scriptFindings 把一個 port 的 NSE 腳本結果轉為弱點 findings

含結構化 CVE 表格（vulners）者 每個 CVE 一筆 severity 取 CVSS 分數
其餘腳本每支一筆 輸出含 VULNERABLE 視為 HIGH 否則 LOW
*/
func scriptFindings(host string, p nmapPort) []model.Finding {
	out := make([]model.Finding, 0)
	for _, sc := range p.Scripts {
		cves := collectCVEs(sc.Tables)
		if len(cves) > 0 {
			for _, c := range cves {
				f := model.Finding{
					Engine:           binaryName,
					Category:         model.CategoryVA,
					RuleID:           c.id,
					Title:            fmt.Sprintf("%s %s", serviceName(p.Service), c.id),
					Severity:         core.SeverityFromCVSS(c.cvss),
					Host:             host,
					Port:             p.PortID,
					References:       []string{c.id},
					UniqueIDFromTool: host + ":" + p.PortID + ":" + c.id,
				}
				if c.cvss > 0 {
					score := c.cvss
					f.CVSSScore = &score
				}
				f.HashCode = core.Fingerprint(f)
				out = append(out, f)
			}
			continue
		}

		/* 無結構化 CVE 的一般腳本 以輸出文字建立單筆 finding */
		output := strings.TrimSpace(sc.Output)
		if output == "" {
			continue
		}
		sev := model.SeverityLow
		if strings.Contains(strings.ToUpper(output), "VULNERABLE") {
			sev = model.SeverityHigh
		}
		f := model.Finding{
			Engine:           binaryName,
			Category:         model.CategoryVA,
			RuleID:           "nmap-" + sc.ID,
			Title:            "NSE " + sc.ID,
			Description:      truncate(output, scriptSnippetMax),
			Severity:         sev,
			Host:             host,
			Port:             p.PortID,
			Snippet:          truncate(output, scriptSnippetMax),
			UniqueIDFromTool: host + ":" + p.PortID + ":" + sc.ID,
		}
		f.HashCode = core.Fingerprint(f)
		out = append(out, f)
	}
	return out
}

/* cveEntry 為從 vulners 等結構化腳本抽出的單一 CVE id 與 CVSS 分數 */
type cveEntry struct {
	id   string
	cvss float64
}

/*
	collectCVEs 遞迴走訪 NSE table 抽出 CVE 條目

vulners 以巢狀 table 每個子 table 含 elem id=CVE-xxxx cvss=7.5 逐一收集
去重同一 CVE 只取一次 保留首見的 CVSS
*/
func collectCVEs(tables []nmapTable) []cveEntry {
	seen := map[string]bool{}
	out := make([]cveEntry, 0)
	var walk func(ts []nmapTable)
	walk = func(ts []nmapTable) {
		for _, t := range ts {
			id, cvss := "", 0.0
			for _, e := range t.Elems {
				switch e.Key {
				case "id":
					v := strings.TrimSpace(e.Value)
					if strings.HasPrefix(strings.ToUpper(v), "CVE-") {
						id = strings.ToUpper(v)
					}
				case "cvss":
					if f, err := strconv.ParseFloat(strings.TrimSpace(e.Value), 64); err == nil {
						cvss = f
					}
				}
			}
			if id != "" && !seen[id] {
				seen[id] = true
				out = append(out, cveEntry{id: id, cvss: cvss})
			}
			walk(t.Tables)
		}
	}
	walk(tables)
	return out
}

/* serviceName 取服務顯示名 供 CVE finding 標題 無名稱時回 service */
func serviceName(svc nmapService) string {
	if svc.Name != "" {
		return svc.Name
	}
	return "service"
}

/* truncate 將字串裁到上限長度 超過時附省略符 供腳本輸出入庫 */
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}

/* hostLabel 從 host 取最佳顯示名稱 優先 hostname 其次 address */
func hostLabel(h nmapHost) string {
	for _, hn := range h.Hostnames.Hostnames {
		if hn.Name != "" {
			return hn.Name
		}
	}
	for _, a := range h.Addresses {
		if a.Addr != "" {
			return a.Addr
		}
	}
	return ""
}

/* buildServiceSnippet 組服務描述字串 */
func buildServiceSnippet(svc nmapService) string {
	parts := make([]string, 0, 4)
	if svc.Name != "" {
		parts = append(parts, svc.Name)
	}
	if svc.Product != "" {
		parts = append(parts, svc.Product)
	}
	if svc.Version != "" {
		parts = append(parts, svc.Version)
	}
	if svc.Extra != "" {
		parts = append(parts, "("+svc.Extra+")")
	}
	return strings.Join(parts, " ")
}
