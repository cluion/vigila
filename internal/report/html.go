package report

import (
	"bytes"
	"html/template"

	"github.com/cluion/vigila/internal/store/sqlc"
)

/* GenerateHTML 產生 HTML 報告 可直接用瀏覽器開啟

內嵌暗色主題樣式 含摘要卡 findings 表格 */
func GenerateHTML(scan sqlc.Scan, runs []sqlc.EngineRun, findings []sqlc.Finding) (string, error) {
	data := BuildReportData(scan, runs, findings)

	tmpl, err := template.New("report").Parse(htmlTemplate)
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

/* htmlTemplate 為 HTML 報告模板 內嵌暗色主題 */
const htmlTemplate = `<!DOCTYPE html>
<html lang="zh-Hant">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Vigila 報告 {{.Scan.ID}}</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
:root {
  --bg:#0f1117; --card:#1a1d27; --hover:#232733; --border:#2a2e3a;
  --text:#e4e6eb; --dim:#8b8f9a; --accent:#6366f1;
  --critical:#dc2626; --high:#ea580c; --medium:#ca8a04; --low:#2563eb; --unknown:#6b7280;
}
body { background:var(--bg); color:var(--text); font-family:system-ui,sans-serif; font-size:14px; line-height:1.5; padding:24px; max-width:1200px; margin:0 auto; }
h1 { font-size:24px; margin-bottom:4px; }
.meta { color:var(--dim); font-size:13px; margin-bottom:20px; }
.stats { display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin-bottom:24px; }
.stat { background:var(--card); border:1px solid var(--border); border-radius:8px; padding:16px; text-align:center; }
.stat .n { font-size:28px; font-weight:700; }
.stat .l { font-size:11px; color:var(--dim); text-transform:uppercase; margin-top:4px; }
h2 { font-size:18px; margin-bottom:12px; }
.engines { margin-bottom:20px; }
.engine { display:inline-block; background:var(--border); color:var(--dim); padding:2px 8px; border-radius:4px; font-size:12px; margin-right:6px; }
table { width:100%; border-collapse:collapse; background:var(--card); border-radius:8px; overflow:hidden; }
th { background:var(--hover); text-align:left; padding:10px 12px; font-size:11px; color:var(--dim); text-transform:uppercase; border-bottom:1px solid var(--border); }
td { padding:10px 12px; border-bottom:1px solid var(--border); vertical-align:top; }
tr:last-child td { border-bottom:none; }
.badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; white-space:nowrap; }
.b-CRITICAL{background:var(--critical);color:#fff}
.b-HIGH{background:var(--high);color:#fff}
.b-MEDIUM{background:var(--medium);color:#fff}
.b-LOW{background:var(--low);color:#fff}
.b-UNKNOWN{background:var(--unknown);color:#fff}
.title { font-weight:500; }
.rule { color:var(--dim); font-size:12px; font-family:monospace; }
.loc { color:var(--dim); font-size:12px; font-family:monospace; }
.snippet { background:var(--bg); padding:6px; border-radius:4px; font-family:monospace; font-size:12px; margin-top:4px; white-space:pre-wrap; word-break:break-all; color:var(--dim); }
.fix { color:#16a34a; font-size:12px; margin-top:2px; }
</style>
</head>
<body>
<h1>Vigila 安全掃描報告</h1>
<div class="meta">
  掃描 ID {{.Scan.ID}}<br>
  目標 {{.Scan.Target}}<br>
  建立時間 {{.Scan.CreatedAt}}
</div>

<div class="stats">
  <div class="stat"><div class="n" style="color:var(--critical)">{{.Summary.Critical}}</div><div class="l">Critical</div></div>
  <div class="stat"><div class="n" style="color:var(--high)">{{.Summary.High}}</div><div class="l">High</div></div>
  <div class="stat"><div class="n" style="color:var(--medium)">{{.Summary.Medium}}</div><div class="l">Medium</div></div>
  <div class="stat"><div class="n" style="color:var(--low)">{{.Summary.Low}}</div><div class="l">Low</div></div>
  <div class="stat"><div class="n">{{.Summary.Total}}</div><div class="l">總計</div></div>
</div>

<div class="engines">
  <h2>引擎執行</h2>
  {{range .EngineRuns}}
  <span class="engine">{{.Engine}} ({{.Category}}) — {{.Status}} {{if .DurationMs}}· {{.DurationMs}}ms{{end}}</span>
  {{end}}
</div>

<h2>漏洞清單 共 {{.Summary.Total}} 個</h2>

{{if .Findings}}
<table>
<thead>
<tr><th>嚴重度</th><th>漏洞</th><th>引擎</th><th>位置</th></tr>
</thead>
<tbody>
{{range .Findings}}
<tr>
<td><span class="badge b-{{.Severity}}">{{.Severity}}</span></td>
<td>
<div class="title">{{.Title}}</div>
<div class="rule">{{.RuleID}}</div>
{{if .Description}}<div class="rule" style="margin-top:4px">{{.Description}}</div>{{end}}
{{if .FixedVersion}}<div class="fix">修復版本 {{.FixedVersion}}</div>{{end}}
{{if .Snippet}}<div class="snippet">{{.Snippet}}</div>{{end}}
</td>
<td><span class="engine">{{.Engine}}</span><div class="rule" style="margin-top:2px">{{.Category}}</div></td>
<td class="loc">
{{if .FilePath}}{{.FilePath}}<br>{{end}}
{{if .StartLine}}第 {{.StartLine}} 行{{end}}
{{if .PkgName}}<br>{{.PkgName}} @ {{.InstalledVersion}}{{end}}
</td>
</tr>
{{end}}
</tbody>
</table>
{{else}}
<p style="color:var(--dim);text-align:center;padding:48px">沒有發現漏洞</p>
{{end}}

</body>
</html>`
