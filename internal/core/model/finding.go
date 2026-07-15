// Package model 為跨引擎統一的漏洞模型
package model

/* Category 標註掃描類別 */
type Category string

const (
	CategorySAST   Category = "SAST"
	CategorySCA    Category = "SCA"
	CategorySecret Category = "SECRET"
	CategoryDAST   Category = "DAST"
	CategoryVA     Category = "VA"
)

/* Severity 統一 5 級嚴重度 數字越大越嚴重 */
type Severity string

const (
	SeverityUnknown  Severity = "UNKNOWN"
	SeverityLow      Severity = "LOW"
	SeverityMedium   Severity = "MEDIUM"
	SeverityHigh     Severity = "HIGH"
	SeverityCritical Severity = "CRITICAL"
)

/* SeverityRank 用於排序 */
var SeverityRank = map[Severity]int{
	SeverityUnknown:  0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

/* Finding 是引擎輸出標準化後的統一漏洞表示 */
type Finding struct {
	Engine           string    `json:"engine"`
	Category         Category  `json:"category"`
	RuleID           string    `json:"rule_id"`
	Title            string    `json:"title"`
	Description      string    `json:"description,omitempty"`
	Severity         Severity  `json:"severity"`
	CVSSScore        *float64  `json:"cvss_score,omitempty"`
	CVSSVector       string    `json:"cvss_vector,omitempty"`
	CWE              string    `json:"cwe,omitempty"`
	FilePath         string    `json:"file_path,omitempty"`
	StartLine        *int64    `json:"start_line,omitempty"`
	EndLine          *int64    `json:"end_line,omitempty"`
	StartCol         *int64    `json:"start_col,omitempty"`
	EndCol           *int64    `json:"end_col,omitempty"`
	Snippet          string    `json:"snippet,omitempty"`
	PkgName          string    `json:"pkg_name,omitempty"`
	InstalledVersion string    `json:"installed_version,omitempty"`
	FixedVersion     string    `json:"fixed_version,omitempty"`
	SecretType       string    `json:"secret_type,omitempty"`
	References       []string  `json:"references,omitempty"`
	UniqueIDFromTool string    `json:"unique_id_from_tool,omitempty"`
	HashCode         string    `json:"hash_code"`
}

/* ScanTarget 描述掃描目標 */
type ScanTarget struct {
	Path string // 掃描的檔案系統路徑
}

/* EngineRunResult 是單一引擎執行的結果摘要 */
type EngineRunResult struct {
	Engine     string
	Category   Category
	Findings   []Finding
	DurationMs int64
	ExitCode   int
	Error      error
}
