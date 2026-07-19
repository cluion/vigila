// Package nmap 為 Nmap VA 引擎 adapter
//
// Nmap 是網路服務偵測工具 target 為 host 或 IP 如 192.168.1.10
// 本 adapter 用 -sV 做服務版本偵測 -oX - 輸出 XML 到 stdout
// 每個 open port 產生一筆 finding 記錄服務與版本資訊
// CVE 偵測 --script vuln 留待後續 本輪先做服務清單
//
// 授權 Nmap 為 GPL-2.0 Vigila 以 subprocess 呼叫不連結程式碼
// 與既有 TruffleHog AGPL 同為外部 binary 不影響 Vigila 的 MIT 授權
package nmap

import (
	"context"
	"encoding/xml"
	"fmt"
	"runtime"
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
-oX - 輸出 XML 到 stdout
*/
func (s *Scanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	args := []string{
		"-sV",
		"-oX", "-",
	}
	args = append(args, opts.ExtraArgs...)
	args = append(args, target)
	return binaryName, args
}

/* Run 執行掃描 用共用 subprocess 實作 stdout 即 XML */
func (s *Scanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	binary, args := s.BuildCommand(target, opts)
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
	PortID  string      `xml:"portid,attr"`
	Proto   string      `xml:"protocol,attr"`
	State   nmapState   `xml:"state"`
	Service nmapService `xml:"service"`
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
		}
	}

	return findings, nil
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
