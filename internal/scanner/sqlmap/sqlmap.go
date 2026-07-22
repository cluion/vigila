// Package sqlmap 為 SQLMap SQL 注入偵測器 DAST adapter
//
// SQLMap 對帶參數的 URL 主動探測 SQL 注入 target 為 URL
// SQLMap 無機器可讀輸出格式 故解析其 stdout 的注入點區塊（Parameter/Type 區段）
// 每個可注入參數產一筆 finding SQL 注入風險高一律 HIGH
//
// stdout 不含目標 URL 故 Run 於輸出前綴一行 vigila-target: <url> 供 Parse 取回 URL
// SQLMap 為 Python 工具 需原生安裝或用 Parrot 維護的 Docker image 見 InstallHint
// 授權 GPL-2.0 Vigila 以 subprocess 呼叫不連結程式碼 不影響 MIT 授權
package sqlmap

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/cluion/vigila/internal/core"
	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

const binaryName = "sqlmap"

/* targetMarker 為 Run 前綴於 stdout 的目標標記 供 Parse 取回原始 URL */
const targetMarker = "vigila-target:"

/* Scanner 為 SQLMap adapter 實作 */
type Scanner struct{}

func init() { scanner.Register(&Scanner{}) }

func (s *Scanner) Name() string             { return binaryName }
func (s *Scanner) Category() model.Category { return model.CategoryDAST }
func (s *Scanner) Binary() string           { return binaryName }
func (s *Scanner) VersionArgs() []string    { return []string{"--version"} }

/* TargetKinds sqlmap 對帶參數的完整網址探測 只吃 URL */
func (s *Scanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetURL}
}

/* InstallHint sqlmap 安裝指引 docker 執行請用面板 Docker 開關 */
func (s *Scanner) InstallHint() scanner.InstallHint {
	return scanner.InstallHint{
		DocsURL: "https://github.com/sqlmapproject/sqlmap#installation",
		Command: "brew install sqlmap",
	}
}

/* CheckInstalled 確認 sqlmap 可用 系統 sqlmap 或已勾選 sqlmap docker profile 皆可 */
func (s *Scanner) CheckInstalled() error {
	return scanner.CheckBinary(binaryName)
}

/*
	BuildCommand 組 sqlmap 掃描指令

-u <target> 指定帶參數的目標 URL
--batch 非互動 全用預設答案
--disable-coloring 關閉色碼 讓 stdout 可穩定解析
--flush-session 不沿用上次 session 確保每次為全新探測
*/
func (s *Scanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	args := []string{
		"-u", target,
		"--batch",
		"--disable-coloring",
		"--flush-session",
	}
	args = append(args, opts.ExtraArgs...)
	return binaryName, args
}

/*
	Run 執行掃描 依來源分流 stdout 即注入點報告

輸出前綴 vigila-target 標記讓 Parse 取回目標 URL（sqlmap stdout 不含完整 URL）
docker 來源用 Parrot 維護的 image 不掛載 直接把 -u <url> 傳入容器
*/
func (s *Scanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	binary, args := s.BuildCommand(target, opts)

	var res *scanner.Result
	var err error
	if scanner.ResolveSourceFor(s.Name(), binary) == scanner.SourceDocker {
		res, err = scanner.DockerRunNoMount(ctx, s.Name(), args)
	} else {
		res, err = scanner.DefaultRun(ctx, binary, args)
	}
	if err != nil {
		return nil, err
	}

	/* 前綴目標標記 供 Parse 取回 URL 不修改 sqlmap 原始輸出的其餘內容 */
	header := []byte(targetMarker + " " + target + "\n")
	res.RawOutput = append(header, res.RawOutput...)
	return res, nil
}

/* ExitCodeIsFindings sqlmap 不以 exit code 表達有無注入點 一律 false */
func (s *Scanner) ExitCodeIsFindings(code int) bool {
	return false
}

/*
	Parse 解析 sqlmap stdout 的注入點區塊

先取 vigila-target 標記還原目標 URL 與 host
逐行掃 Parameter: <名> (<方法>) 起一筆 finding 收其下 Type/Title 描述注入手法
每個可注入參數一筆 finding SQL 注入一律 HIGH 套用 DAST fingerprint engine + rule_id + url
*/
func (s *Scanner) Parse(raw []byte) ([]model.Finding, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return []model.Finding{}, nil
	}

	target := ""
	findings := make([]model.Finding, 0)
	var cur *injection

	flush := func() {
		if cur != nil {
			findings = append(findings, cur.toFinding(target))
			cur = nil
		}
	}

	sc := bufio.NewScanner(bytes.NewReader(raw))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)

		if target == "" {
			if v, ok := strings.CutPrefix(trimmed, targetMarker); ok {
				target = strings.TrimSpace(v)
				continue
			}
		}

		if param, method, ok := parseParameterLine(trimmed); ok {
			flush()
			cur = &injection{param: param, method: method}
			continue
		}

		if cur == nil {
			continue
		}

		/* 遇到區塊結束標記 --- 收束當前注入點 */
		if trimmed == "---" {
			flush()
			continue
		}
		if t, ok := strings.CutPrefix(trimmed, "Type:"); ok {
			cur.types = append(cur.types, strings.TrimSpace(t))
		}
	}
	flush()

	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("sqlmap 輸出讀取失敗: %w", err)
	}
	return findings, nil
}

/* injection 為解析中的單一注入點 param 為參數名 method 為 HTTP 方法 types 為注入手法清單 */
type injection struct {
	param  string
	method string
	types  []string
}

/*
	toFinding 把注入點轉為統一 Finding

Title 標參數與方法 Description 列出注入手法 host 由目標 URL 推導
UniqueIDFromTool 以參數+方法區分同 URL 多參數 fingerprint 走 engine + rule_id + url
*/
func (in *injection) toFinding(target string) model.Finding {
	desc := "可注入手法: " + strings.Join(in.types, "、")
	f := model.Finding{
		Engine:           binaryName,
		Category:         model.CategoryDAST,
		RuleID:           "sqlmap-sqli",
		Title:            fmt.Sprintf("參數 %s (%s) 可 SQL 注入", in.param, in.method),
		Description:      desc,
		Severity:         model.SeverityHigh,
		URL:              target,
		Host:             hostOf(target),
		Method:           strings.ToUpper(in.method),
		UniqueIDFromTool: "sqli:" + in.param + ":" + in.method,
	}
	f.HashCode = core.Fingerprint(f)
	return f
}

/*
	parseParameterLine 解析 Parameter: <名> (<方法>) 一行

回傳參數名 方法 與是否命中 非此格式回 false
*/
func parseParameterLine(line string) (string, string, bool) {
	rest, ok := strings.CutPrefix(line, "Parameter:")
	if !ok {
		return "", "", false
	}
	rest = strings.TrimSpace(rest)
	open := strings.LastIndex(rest, "(")
	close := strings.LastIndex(rest, ")")
	if open < 0 || close < open {
		return strings.TrimSpace(rest), "", true
	}
	name := strings.TrimSpace(rest[:open])
	method := strings.TrimSpace(rest[open+1 : close])
	return name, method, true
}

/* hostOf 從目標 URL 取 host 解析失敗回空字串 */
func hostOf(target string) string {
	u, err := url.Parse(target)
	if err != nil {
		return ""
	}
	return u.Hostname()
}
