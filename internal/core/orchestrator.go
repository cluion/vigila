// Package core 為掃描編排核心
//
// orchestrator 串接引擎執行 parse 寫入 DB
// CLI 與 Web 都呼叫同一份邏輯
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/sbom"
	"github.com/cluion/vigila/internal/scanner"
	"github.com/cluion/vigila/internal/store/sqlc"
	"github.com/oklog/ulid/v2"
)

/*
	EventFn 為掃描事件回呼 供 SSE 推播

型別為 scan_started scan_completed engine_started engine_completed
若為 nil 則不推播 CLI 場景不需要
*/
type EventFn func(eventType string, data interface{})

/* Orchestrator 協調掃描的完整流程 */
type Orchestrator struct {
	q             *sqlc.Queries
	onEvent       EventFn
	triggerSource string
	sbom          bool
	projectName   string // 非空時覆蓋由 target 推導的 project 名 供上傳等 target 為暫存路徑的情境
}

/* New 建立 Orchestrator 需傳入 sqlc Queries */
func New(q *sqlc.Queries) *Orchestrator {
	return &Orchestrator{q: q, triggerSource: "cli"}
}

/* WithSBOM 設定掃描後是否順帶產生 SBOM 僅對本機路徑目標生效 */
func (o *Orchestrator) WithSBOM(enabled bool) *Orchestrator {
	o.sbom = enabled
	return o
}

/* WithEvent 設定事件回呼 供 Web 場景推播 SSE */
func (o *Orchestrator) WithEvent(fn EventFn) *Orchestrator {
	o.onEvent = fn
	return o
}

/* WithTriggerSource 設定掃描觸發來源 cli 或 web 預設 cli */
func (o *Orchestrator) WithTriggerSource(src string) *Orchestrator {
	o.triggerSource = src
	return o
}

/*
	WithProjectName 覆蓋 project 名稱

上傳掃描的 target 為隨機暫存目錄 若用它推導 project 名 同一壓縮包每次都建新 project
去重與 diff 皆失效 故以穩定的壓縮包檔名作 project 名 讓重複上傳歸於同一 project
*/
func (o *Orchestrator) WithProjectName(name string) *Orchestrator {
	o.projectName = name
	return o
}

/* emit 推播事件 onEvent 為 nil 時跳過 */
func (o *Orchestrator) emit(eventType string, data interface{}) {
	if o.onEvent != nil {
		o.onEvent(eventType, data)
	}
}

/* ScanResult 是單次掃描的彙整結果 */
type ScanResult struct {
	ScanID       string
	Total        int
	BySeverity   map[model.Severity]int
	ByEngine     map[string]int
	DurationMs   int64
	SBOMPackages int      // 產出的 SBOM 套件數 未產 SBOM 為 0
	SBOMErr      error    // SBOM 產生錯誤 不影響 scan 成敗
	Ran          int      // 實際執行的引擎數 未安裝而略過的不計入
	Skipped      []string // 因未安裝而略過的引擎名稱
	Err          error
}

/* newScanResult 建立空結果 */
func newScanResult(scanID string) *ScanResult {
	return &ScanResult{
		ScanID:     scanID,
		BySeverity: map[model.Severity]int{},
		ByEngine:   map[string]int{},
	}
}

/* RunSingle 執行單一引擎掃描 完整流程 */
func (o *Orchestrator) RunSingle(ctx context.Context, s scanner.Scanner, target string, opts scanner.Options) (*ScanResult, error) {
	scanCtx, err := o.beginScan(ctx, target, "single", "", false)
	if err != nil {
		return nil, err
	}
	return o.runAndFinish(ctx, scanCtx, []scanner.Scanner{s}, target, map[string]scanner.Options{s.Name(): opts})
}

/* RunMultiple 執行多引擎掃描 共用同一個 scan */
func (o *Orchestrator) RunMultiple(ctx context.Context, scanners []scanner.Scanner, target string, opts scanner.Options) (*ScanResult, error) {
	scanCtx, err := o.beginScan(ctx, target, "multi", "", false)
	if err != nil {
		return nil, err
	}
	optsMap := map[string]scanner.Options{}
	for _, s := range scanners {
		optsMap[s.Name()] = opts
	}
	return o.runAndFinish(ctx, scanCtx, scanners, target, optsMap)
}

/* RunProfile 依 profile 名稱執行流程掃描 記錄 profile 名於 scan */
func (o *Orchestrator) RunProfile(ctx context.Context, profileName string, target string, opts scanner.Options) (*ScanResult, error) {
	profile, err := GetProfile(profileName)
	if err != nil {
		return nil, err
	}
	scanners, err := profile.Resolve()
	if err != nil {
		return nil, err
	}
	scanCtx, err := o.beginScan(ctx, target, "profile", profile.Name, profile.FailFast)
	if err != nil {
		return nil, err
	}
	optsMap := map[string]scanner.Options{}
	for _, s := range scanners {
		optsMap[s.Name()] = opts
	}
	return o.runAndFinish(ctx, scanCtx, scanners, target, optsMap)
}

/*
	RunSBOMOnly 只產 SBOM 不跑漏洞引擎

建立一筆 type sbom 的 scan 僅產出 SBOM artifact 供不需漏洞掃描只要物料清單的情境
僅支援本機路徑目標 狀態依 SBOM 產生成敗決定
*/
func (o *Orchestrator) RunSBOMOnly(ctx context.Context, target string) (*ScanResult, error) {
	if scanner.DetectTargetKind(target) != scanner.TargetPath {
		return nil, fmt.Errorf("SBOM 僅支援本機路徑目標 %s 非路徑", target)
	}

	sc, err := o.beginScan(ctx, target, "sbom", "", false)
	if err != nil {
		return nil, err
	}

	result := newScanResult(sc.scanID)
	start := time.Now()
	o.emit("scan_started", map[string]interface{}{"scan_id": sc.scanID, "target": target})

	o.generateSBOM(ctx, sc, result)
	result.DurationMs = time.Since(start).Milliseconds()

	completed := time.Now()
	status := "completed"
	if result.SBOMErr != nil {
		status = "failed"
	}
	if _, err := o.q.UpdateScanStatus(ctx, sqlc.UpdateScanStatusParams{
		ID:          sc.scanID,
		Status:      status,
		StartedAt:   &start,
		CompletedAt: &completed,
	}); err != nil {
		log.Printf("更新 SBOM scan %s 最終狀態為 %s 失敗: %v", sc.scanID, status, err)
	}
	o.emit("scan_completed", map[string]interface{}{"scan_id": sc.scanID, "status": status})

	return result, result.SBOMErr
}

/* scanContext 為一次掃描的上下文 含 project scan 起始時間 */
type scanContext struct {
	projectID string
	scanID    string
	target    string
	started   time.Time
	failFast  bool
}

/* beginScan 建立 project 與 scan 回傳上下文 profileName 非空時記錄於 scan */
func (o *Orchestrator) beginScan(ctx context.Context, target string, scanType string, profileName string, failFast bool) (*scanContext, error) {
	projectName := o.projectName
	if projectName == "" {
		projectName = deriveProjectName(target)
	}
	projectID := ulid.Make().String()
	project, err := o.q.UpsertProjectByName(ctx, sqlc.UpsertProjectByNameParams{
		ID:   projectID,
		Name: projectName,
	})
	if err != nil {
		return nil, fmt.Errorf("建立 project 失敗: %w", err)
	}

	now := time.Now()
	scanID := ulid.Make().String()
	scanParams := sqlc.CreateScanParams{
		ID:            scanID,
		ProjectID:     project.ID,
		Target:        target,
		ScanType:      scanType,
		Status:        "running",
		TriggerSource: o.triggerSource,
	}
	if profileName != "" {
		scanParams.Profile = &profileName
	}
	_, err = o.q.CreateScan(ctx, scanParams)
	if err != nil {
		return nil, fmt.Errorf("建立 scan 失敗: %w", err)
	}

	return &scanContext{
		projectID: project.ID,
		scanID:    scanID,
		target:    target,
		started:   now,
		failFast:  failFast,
	}, nil
}

/* runAndFinish 依序執行所有引擎 並更新 scan 最終狀態 */
func (o *Orchestrator) runAndFinish(ctx context.Context, sc *scanContext, scanners []scanner.Scanner, target string, optsMap map[string]scanner.Options) (*ScanResult, error) {
	result := newScanResult(sc.scanID)
	start := time.Now()

	o.emit("scan_started", map[string]interface{}{
		"scan_id": sc.scanID,
		"target":  target,
		"engines": engineNames(scanners),
	})

	for _, s := range scanners {
		o.runEngine(ctx, s, sc, target, optsMap[s.Name()], result)
		if sc.failFast && result.Err != nil {
			break
		}
	}

	if o.sbom {
		o.generateSBOM(ctx, sc, result)
	}

	result.DurationMs = time.Since(start).Milliseconds()

	completed := time.Now()
	status := "completed"
	switch {
	case result.Err != nil:
		status = "failed"
	case result.Ran == 0:
		/* 所有引擎皆未安裝 無一執行 掃描未達成任何目的 標為 failed */
		status = "failed"
		if result.Err == nil && len(result.Skipped) > 0 {
			result.Err = fmt.Errorf("所有引擎皆未安裝 已略過: %s", strings.Join(result.Skipped, " "))
		}
	}
	if _, err := o.q.UpdateScanStatus(ctx, sqlc.UpdateScanStatusParams{
		ID:          sc.scanID,
		Status:      status,
		StartedAt:   &start,
		CompletedAt: &completed,
	}); err != nil {
		/* 更新失敗會讓 scan 停在 running 至少記錄下來供排查 勿靜默吞掉 */
		log.Printf("更新 scan %s 最終狀態為 %s 失敗: %v", sc.scanID, status, err)
	}

	o.emit("scan_completed", map[string]interface{}{
		"scan_id":     sc.scanID,
		"status":      status,
		"total":       result.Total,
		"duration_ms": result.DurationMs,
	})

	return result, result.Err
}

/*
	generateSBOM 對本機路徑目標產 SBOM 存為 scan artifact

僅支援路徑目標 URL host 目標跳過 SBOM 產生或寫入失敗記於 SBOMErr 不影響 scan 成敗
*/
func (o *Orchestrator) generateSBOM(ctx context.Context, sc *scanContext, result *ScanResult) {
	if scanner.DetectTargetKind(sc.target) != scanner.TargetPath {
		result.SBOMErr = fmt.Errorf("SBOM 僅支援本機路徑目標 已跳過")
		return
	}

	o.emit("sbom_started", map[string]interface{}{"scan_id": sc.scanID})

	content, err := sbom.Generate(ctx, sc.target)
	if err != nil {
		result.SBOMErr = err
		o.emit("sbom_completed", map[string]interface{}{"scan_id": sc.scanID, "status": "failed"})
		return
	}

	if _, err := o.q.CreateArtifact(ctx, sqlc.CreateArtifactParams{
		ID:      ulid.Make().String(),
		ScanID:  sc.scanID,
		Type:    "sbom",
		Engine:  sbom.Binary,
		Format:  sbom.Format,
		Content: string(content),
	}); err != nil {
		result.SBOMErr = fmt.Errorf("寫入 SBOM artifact 失敗: %w", err)
		return
	}

	if pkgs, perr := sbom.ParsePackages(content); perr == nil {
		result.SBOMPackages = len(pkgs)
	}
	o.emit("sbom_completed", map[string]interface{}{
		"scan_id":  sc.scanID,
		"status":   "completed",
		"packages": result.SBOMPackages,
	})
}

/* engineNames 取出引擎名稱清單 */
func engineNames(scanners []scanner.Scanner) []string {
	names := make([]string, 0, len(scanners))
	for _, s := range scanners {
		names = append(names, s.Name())
	}
	return names
}

/*
	runEngine 執行單一引擎 建立 engine_run parse findings 寫入 DB

引擎執行失敗不中斷其他引擎 只記錄於 result.Err
*/
func (o *Orchestrator) runEngine(ctx context.Context, s scanner.Scanner, sc *scanContext, target string, opts scanner.Options, result *ScanResult) {
	o.emit("engine_started", map[string]interface{}{
		"scan_id": sc.scanID,
		"engine":  s.Name(),
	})

	/*
		引擎未安裝屬預期常態 尤其 --engine all 時本機未必裝齊
		不視為掃描失敗 記為 skipped 的 engine_run 保持事件與 DB 一致
		不污染 result.Err 讓其他已裝引擎的結果仍計為 completed
	*/
	if err := s.CheckInstalled(); err != nil {
		result.Skipped = append(result.Skipped, s.Name())
		msg := fmt.Sprintf("引擎未安裝: %v", err)
		_, _ = o.q.CreateEngineRun(ctx, sqlc.CreateEngineRunParams{
			ID:           ulid.Make().String(),
			ScanID:       sc.scanID,
			Engine:       s.Name(),
			Category:     string(s.Category()),
			Status:       "skipped",
			ErrorMessage: &msg,
		})
		o.emit("engine_completed", map[string]interface{}{
			"scan_id": sc.scanID,
			"engine":  s.Name(),
			"status":  "skipped",
		})
		return
	}
	result.Ran++

	engineRunID := ulid.Make().String()
	runStarted := time.Now()
	res, runErr := s.Run(ctx, target, opts)
	runCompleted := time.Now()

	durationMs := int64(0)
	exitCode := int64(-1)
	var cmdStr *string
	if res != nil {
		durationMs = res.DurationMs
		exitCode = int64(res.ExitCode)
		cs := res.Command
		cmdStr = &cs
	}

	/* 非零且非 findings 慣例的 exit code 視為引擎執行失敗 不採信其輸出 */
	if runErr == nil && res != nil && res.ExitCode != 0 && !s.ExitCodeIsFindings(res.ExitCode) {
		runErr = fmt.Errorf("%s 以非預期 exit code %d 結束", s.Name(), res.ExitCode)
	}

	runStatus := "completed"
	errMsg := (*string)(nil)
	if runErr != nil {
		runStatus = "failed"
		e := runErr.Error()
		errMsg = &e
	}

	engineRun, err := o.q.CreateEngineRun(ctx, sqlc.CreateEngineRunParams{
		ID:           engineRunID,
		ScanID:       sc.scanID,
		Engine:       s.Name(),
		Category:     string(s.Category()),
		Command:      cmdStr,
		Status:       runStatus,
		ExitCode:     int64Ptr(exitCode),
		DurationMs:   int64Ptr(durationMs),
		ErrorMessage: errMsg,
		StartedAt:    &runStarted,
		CompletedAt:  &runCompleted,
	})
	if err != nil {
		result.Err = fmt.Errorf("建立 engine_run 失敗: %w", err)
		return
	}

	if runErr != nil {
		result.Err = runErr
		o.emit("engine_completed", map[string]interface{}{
			"scan_id": sc.scanID,
			"engine":  s.Name(),
			"status":  runStatus,
		})
		return
	}

	if res == nil {
		return
	}

	findings, perr := s.Parse(res.RawOutput)
	if perr != nil {
		result.Err = fmt.Errorf("parse %s 輸出失敗: %w", s.Name(), perr)
		return
	}

	for _, f := range findings {
		params := toUpsertParams(f, sc.projectID, sc.scanID, engineRun.ID)
		row, err := o.q.UpsertFinding(ctx, params)
		if err != nil {
			result.Err = fmt.Errorf("寫入 finding 失敗: %w", err)
			return
		}
		/* 記錄本次掃描觀察到的 finding 供 diff 還原歷史集合 */
		if err := o.q.CreateScanFinding(ctx, sqlc.CreateScanFindingParams{
			ScanID:    sc.scanID,
			FindingID: row.ID,
			HashCode:  row.HashCode,
		}); err != nil {
			result.Err = fmt.Errorf("寫入 scan_finding 失敗: %w", err)
			return
		}
		result.Total++
		result.BySeverity[f.Severity]++
		result.ByEngine[s.Name()]++
	}

	o.emit("engine_completed", map[string]interface{}{
		"scan_id":     sc.scanID,
		"engine":      s.Name(),
		"status":      runStatus,
		"findings":    len(findings),
		"duration_ms": durationMs,
	})
}

/* toUpsertParams 將 model.Finding 轉為 sqlc UpsertFindingParams */
func toUpsertParams(f model.Finding, projectID, scanID, engineRunID string) sqlc.UpsertFindingParams {
	p := sqlc.UpsertFindingParams{
		ID:          ulid.Make().String(),
		ProjectID:   projectID,
		ScanID:      scanID,
		EngineRunID: engineRunID,
		Engine:      f.Engine,
		Category:    string(f.Category),
		RuleID:      f.RuleID,
		Title:       f.Title,
		Severity:    string(f.Severity),
		HashCode:    f.HashCode,
	}
	if f.Description != "" {
		p.Description = &f.Description
	}
	if f.CVSSScore != nil {
		p.CvssScore = f.CVSSScore
	}
	if f.CVSSVector != "" {
		p.CvssVector = &f.CVSSVector
	}
	if f.CWE != "" {
		p.Cwe = &f.CWE
	}
	if f.FilePath != "" {
		p.FilePath = &f.FilePath
	}
	if f.StartLine != nil {
		p.StartLine = f.StartLine
	}
	if f.EndLine != nil {
		p.EndLine = f.EndLine
	}
	if f.StartCol != nil {
		p.StartCol = f.StartCol
	}
	if f.EndCol != nil {
		p.EndCol = f.EndCol
	}
	if f.Snippet != "" {
		p.Snippet = &f.Snippet
	}
	if f.PkgName != "" {
		p.PkgName = &f.PkgName
	}
	if f.InstalledVersion != "" {
		p.InstalledVersion = &f.InstalledVersion
	}
	if f.FixedVersion != "" {
		p.FixedVersion = &f.FixedVersion
	}
	if f.SecretType != "" {
		p.SecretType = &f.SecretType
	}
	if f.URL != "" {
		p.Url = &f.URL
	}
	if f.Host != "" {
		p.Host = &f.Host
	}
	if f.Port != "" {
		p.Port = &f.Port
	}
	if f.Method != "" {
		p.Method = &f.Method
	}
	if f.UniqueIDFromTool != "" {
		p.UniqueIDFromTool = &f.UniqueIDFromTool
	}
	if len(f.References) > 0 {
		if b, err := json.Marshal(f.References); err == nil {
			s := string(b)
			p.ReferencesJson = &s
		}
	}
	return p
}

/* int64Ptr 將 int64 轉為指標 負值回 nil */
func int64Ptr(v int64) *int64 {
	if v < 0 {
		return nil
	}
	return &v
}

/*
	deriveProjectName 從 target 推導 project 名稱

路徑目標取檔名 如 /tmp/myapp → myapp
URL 目標取 host 如 http://host/path → host
純 host/IP 直接使用 如 192.168.1.10 → 192.168.1.10
*/
func deriveProjectName(target string) string {
	/* 含 scheme 視為 URL 取 host */
	if strings.Contains(target, "://") {
		if u, err := url.Parse(target); err == nil && u.Host != "" {
			return u.Host
		}
	}

	/* 含連接埠的 host/IP 直接使用 如 scanme.nmap.org:8080 或 192.168.1.10 */
	if strings.Contains(target, ":") && !strings.ContainsAny(target, "/\\") {
		return target
	}

	name := filepath.Base(target)
	if name == "." || name == "" || name == "/" {
		return "default"
	}
	return name
}
