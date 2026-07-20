package report

import (
	"encoding/json"
	"testing"

	"github.com/cluion/vigila/internal/store/sqlc"
)

/*
	sarifDoc 為 SARIF JSON 的最小解析結構 供測試斷言用

只取驗證需要的欄位 version runs[].tool.results[].level properties
*/
type sarifDoc struct {
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool struct {
		Driver struct {
			Name string `json:"name"`
		} `json:"driver"`
	} `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	Level      string                 `json:"level"`
	Message    sarifMsg               `json:"message"`
	Locations  []sarifLocation        `json:"locations"`
	Properties map[string]interface{} `json:"properties"`
}

type sarifMsg struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation struct {
		ArtifactLocation struct {
			URI string `json:"uri"`
		} `json:"artifactLocation"`
		Region *sarifRegion `json:"region"`
	} `json:"physicalLocation"`
}

type sarifRegion struct {
	StartLine *int `json:"startLine"`
	EndLine   *int `json:"endLine"`
}

/* parseSarif 把 GenerateSARIF 產出解析為 sarifDoc */
func parseSarif(t *testing.T, out string) sarifDoc {
	t.Helper()
	var doc sarifDoc
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("SARIF 產出非合法 JSON: %v", out)
	}
	return doc
}

/* TestGenerateSARIFVersion 產出應為 SARIF 2.1.0 */
func TestGenerateSARIFVersion(t *testing.T) {
	out, err := GenerateSARIF(sqlc.Scan{}, []sqlc.EngineRun{{Engine: "semgrep"}}, nil)
	if err != nil {
		t.Fatalf("GenerateSARIF 失敗: %v", err)
	}
	doc := parseSarif(t, out)
	if doc.Version != "2.1.0" {
		t.Errorf("version = %q 預期 2.1.0", doc.Version)
	}
}

/*
	TestGenerateSARIFSeverityMapping 驗證 severity 對 level 與 security-severity 映射

CRITICAL HIGH → error MEDIUM → warning LOW UNKNOWN → note
*/
func TestGenerateSARIFSeverityMapping(t *testing.T) {
	findings := []sqlc.Finding{
		{Engine: "semgrep", Severity: "CRITICAL", RuleID: "r1", Title: "c"},
		{Engine: "semgrep", Severity: "HIGH", RuleID: "r2", Title: "h"},
		{Engine: "semgrep", Severity: "MEDIUM", RuleID: "r3", Title: "m"},
		{Engine: "semgrep", Severity: "LOW", RuleID: "r4", Title: "l"},
		{Engine: "semgrep", Severity: "UNKNOWN", RuleID: "r5", Title: "u"},
	}
	runs := []sqlc.EngineRun{{Engine: "semgrep"}}

	out, err := GenerateSARIF(sqlc.Scan{}, runs, findings)
	if err != nil {
		t.Fatalf("GenerateSARIF 失敗: %v", err)
	}
	doc := parseSarif(t, out)

	if len(doc.Runs) != 1 {
		t.Fatalf("應有 1 個 run 實際 %d", len(doc.Runs))
	}
	results := doc.Runs[0].Results
	if len(results) != 5 {
		t.Fatalf("應有 5 個 result 實際 %d", len(results))
	}

	wantLevels := map[string]string{"r1": "error", "r2": "error", "r3": "warning", "r4": "note", "r5": "note"}
	wantScores := map[string]string{"r1": "9.5", "r2": "7.5", "r3": "5.0", "r4": "2.5", "r5": "0.0"}
	for _, r := range results {
		if level, ok := wantLevels[r.RuleID]; ok && r.Level != level {
			t.Errorf("%s level = %q 預期 %q", r.RuleID, r.Level, level)
		}
		if score, ok := wantScores[r.RuleID]; ok {
			if got, _ := r.Properties["security-severity"].(string); got != score {
				t.Errorf("%s security-severity = %q 預期 %q", r.RuleID, got, score)
			}
		}
	}
}

/*
	TestGenerateSARIFSASTLocation SAST finding 以 file path + 行號為 location

含 EndLine 時 region 應帶 endLine（驗證鏈式呼叫未丟失）
*/
func TestGenerateSARIFSASTLocation(t *testing.T) {
	findings := []sqlc.Finding{
		{
			Engine: "semgrep", Severity: "HIGH", RuleID: "sast1", Title: "inj",
			FilePath: strPtr("app/main.py"), StartLine: intPtr(10), EndLine: intPtr(12),
		},
	}
	runs := []sqlc.EngineRun{{Engine: "semgrep"}}

	out, err := GenerateSARIF(sqlc.Scan{}, runs, findings)
	if err != nil {
		t.Fatalf("GenerateSARIF 失敗: %v", err)
	}
	doc := parseSarif(t, out)
	r := doc.Runs[0].Results[0]

	if len(r.Locations) != 1 {
		t.Fatalf("應有 1 個 location 實際 %d", len(r.Locations))
	}
	if r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "app/main.py" {
		t.Errorf("URI = %q 預期 app/main.py", r.Locations[0].PhysicalLocation.ArtifactLocation.URI)
	}
	region := r.Locations[0].PhysicalLocation.Region
	if region == nil {
		t.Fatal("SAST finding 應含 region")
	}
	if region.StartLine == nil || *region.StartLine != 10 {
		t.Errorf("startLine 預期 10 實際 %v", region.StartLine)
	}
	/* 驗證 EndLine 鏈式呼叫未丟失 這是先前懷疑的潛在 bug */
	if region.EndLine == nil || *region.EndLine != 12 {
		t.Errorf("endLine 預期 12 實際 %v region=%+v", region.EndLine, region)
	}
}

/* TestGenerateSARIFDASTLocation DAST finding 無檔案 以 URL 為 location */
func TestGenerateSARIFDASTLocation(t *testing.T) {
	findings := []sqlc.Finding{
		{Engine: "nuclei", Severity: "CRITICAL", RuleID: "dast1", Title: "xss", Url: strPtr("https://x.com/admin")},
	}
	runs := []sqlc.EngineRun{{Engine: "nuclei"}}

	out, _ := GenerateSARIF(sqlc.Scan{}, runs, findings)
	doc := parseSarif(t, out)
	r := doc.Runs[0].Results[0]

	if len(r.Locations) != 1 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "https://x.com/admin" {
		t.Errorf("DAST location URI 應為目標 URL 實際 %+v", r.Locations)
	}
	if got, _ := r.Properties["url"].(string); got != "https://x.com/admin" {
		t.Errorf("DAST url property 應帶 URL 實際 %q", got)
	}
}

/* TestGenerateSARIFVALocation VA finding 以 host:port 為 location */
func TestGenerateSARIFVALocation(t *testing.T) {
	findings := []sqlc.Finding{
		{Engine: "nmap", Severity: "MEDIUM", RuleID: "va1", Title: "ssh open", Host: strPtr("10.0.0.1"), Port: strPtr("22")},
	}
	runs := []sqlc.EngineRun{{Engine: "nmap"}}

	out, _ := GenerateSARIF(sqlc.Scan{}, runs, findings)
	doc := parseSarif(t, out)
	r := doc.Runs[0].Results[0]

	/* host:port 合成單一 URI */
	if len(r.Locations) != 1 || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "10.0.0.1:22" {
		t.Errorf("VA location URI 應為 host:port 實際 %+v", r.Locations)
	}
}

/* TestGenerateSARIFPropertyBag 擴充欄位 CVSS CWE 修復版本套件名應帶入 properties */
func TestGenerateSARIFPropertyBag(t *testing.T) {
	cvss := 7.8
	findings := []sqlc.Finding{
		{
			Engine: "trivy", Category: "SCA", Severity: "HIGH", RuleID: "CVE-2024-1", Title: "vuln",
			CvssScore: &cvss, Cwe: strPtr("CWE-79"),
			FixedVersion: strPtr(">=2.0.0"), PkgName: strPtr("lodash"),
		},
	}
	runs := []sqlc.EngineRun{{Engine: "trivy"}}

	out, _ := GenerateSARIF(sqlc.Scan{}, runs, findings)
	doc := parseSarif(t, out)
	r := doc.Runs[0].Results[0]

	if got, _ := r.Properties["cvss_score"].(string); got != "7.8" {
		t.Errorf("cvss_score property = %q 預期 7.8", got)
	}
	if got, _ := r.Properties["cwe"].(string); got != "CWE-79" {
		t.Errorf("cwe property = %q 預期 CWE-79", got)
	}
	if got, _ := r.Properties["fixed_version"].(string); got != ">=2.0.0" {
		t.Errorf("fixed_version property = %q 預期 >=2.0.0", got)
	}
	if got, _ := r.Properties["pkg_name"].(string); got != "lodash" {
		t.Errorf("pkg_name property = %q 預期 lodash", got)
	}
	/* engine category 為必帶基礎欄位 */
	if got, _ := r.Properties["engine"].(string); got != "trivy" {
		t.Errorf("engine property = %q 預期 trivy", got)
	}
	if got, _ := r.Properties["category"].(string); got != "SCA" {
		t.Errorf("category property = %q 預期 SCA（trivy 類別）", got)
	}
}

/* TestGenerateSARIFMultipleEngines 每引擎一個 run 同檔承載多引擎 */
func TestGenerateSARIFMultipleEngines(t *testing.T) {
	findings := []sqlc.Finding{
		{Engine: "semgrep", Severity: "HIGH", RuleID: "s1", Title: "sast"},
		{Engine: "trivy", Severity: "MEDIUM", RuleID: "t1", Title: "sca"},
		{Engine: "gitleaks", Severity: "CRITICAL", RuleID: "g1", Title: "secret"},
	}
	runs := []sqlc.EngineRun{
		{Engine: "semgrep"}, {Engine: "trivy"}, {Engine: "gitleaks"},
	}

	out, _ := GenerateSARIF(sqlc.Scan{}, runs, findings)
	doc := parseSarif(t, out)

	if len(doc.Runs) != 3 {
		t.Fatalf("應有 3 個 run（每引擎一個）實際 %d", len(doc.Runs))
	}
	/* 每個 run 的 driver name 應為引擎名 */
	names := map[string]bool{}
	for _, run := range doc.Runs {
		names[run.Tool.Driver.Name] = true
	}
	for _, want := range []string{"semgrep", "trivy", "gitleaks"} {
		if !names[want] {
			t.Errorf("缺少 engine %q 的 run", want)
		}
	}
}

/* TestGenerateSARIFEmpty 無 findings 無 runs 仍應產出合法 SARIF */
func TestGenerateSARIFEmpty(t *testing.T) {
	out, err := GenerateSARIF(sqlc.Scan{}, nil, nil)
	if err != nil {
		t.Fatalf("空輸入 GenerateSARIF 失敗: %v", err)
	}
	doc := parseSarif(t, out)
	if doc.Version != "2.1.0" {
		t.Errorf("空輸入 version 仍應為 2.1.0 實際 %q", doc.Version)
	}
}
