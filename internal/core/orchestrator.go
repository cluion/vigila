// Package core 為掃描編排核心
//
// orchestrator 串接引擎執行 parse 寫入 DB
// CLI 與 Web 都呼叫同一份邏輯
package core

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
	"github.com/cluion/vigila/internal/store/sqlc"
	"github.com/oklog/ulid/v2"
)

/* Orchestrator 協調掃描的完整流程 */
type Orchestrator struct {
	q *sqlc.Queries
}

/* New 建立 Orchestrator 需傳入 sqlc Queries */
func New(q *sqlc.Queries) *Orchestrator {
	return &Orchestrator{q: q}
}

/* ScanResult 是單次掃描的彙整結果 */
type ScanResult struct {
	ScanID      string
	Total       int
	BySeverity  map[model.Severity]int
	ByEngine    map[string]int
	DurationMs  int64
	Err         error
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
	scanCtx, err := o.beginScan(ctx, target, "single")
	if err != nil {
		return nil, err
	}
	return o.runAndFinish(ctx, scanCtx, []scanner.Scanner{s}, target, map[string]scanner.Options{s.Name(): opts})
}

/* RunMultiple 執行多引擎掃描 共用同一個 scan */
func (o *Orchestrator) RunMultiple(ctx context.Context, scanners []scanner.Scanner, target string, opts scanner.Options) (*ScanResult, error) {
	scanCtx, err := o.beginScan(ctx, target, "profile")
	if err != nil {
		return nil, err
	}
	optsMap := map[string]scanner.Options{}
	for _, s := range scanners {
		optsMap[s.Name()] = opts
	}
	return o.runAndFinish(ctx, scanCtx, scanners, target, optsMap)
}

/* scanContext 為一次掃描的上下文 含 project scan 起始時間 */
type scanContext struct {
	projectID string
	scanID    string
	target    string
	started   time.Time
}

/* beginScan 建立 project 與 scan 回傳上下文 */
func (o *Orchestrator) beginScan(ctx context.Context, target string, scanType string) (*scanContext, error) {
	projectName := filepath.Base(target)
	if projectName == "." || projectName == "" {
		projectName = "default"
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
	_, err = o.q.CreateScan(ctx, sqlc.CreateScanParams{
		ID:            scanID,
		ProjectID:     project.ID,
		Target:        target,
		ScanType:      scanType,
		Status:        "running",
		TriggerSource: "cli",
	})
	if err != nil {
		return nil, fmt.Errorf("建立 scan 失敗: %w", err)
	}

	return &scanContext{
		projectID: project.ID,
		scanID:    scanID,
		target:    target,
		started:   now,
	}, nil
}

/* runAndFinish 依序執行所有引擎 並更新 scan 最終狀態 */
func (o *Orchestrator) runAndFinish(ctx context.Context, sc *scanContext, scanners []scanner.Scanner, target string, optsMap map[string]scanner.Options) (*ScanResult, error) {
	result := newScanResult(sc.scanID)
	start := time.Now()

	for _, s := range scanners {
		o.runEngine(ctx, s, sc, target, optsMap[s.Name()], result)
	}

	result.DurationMs = time.Since(start).Milliseconds()

	completed := time.Now()
	status := "completed"
	if result.Err != nil {
		status = "failed"
	}
	_, _ = o.q.UpdateScanStatus(ctx, sqlc.UpdateScanStatusParams{
		ID:          sc.scanID,
		Status:      status,
		StartedAt:   &start,
		CompletedAt: &completed,
	})

	return result, result.Err
}

/* runEngine 執行單一引擎 建立 engine_run parse findings 寫入 DB

引擎執行失敗不中斷其他引擎 只記錄於 result.Err */
func (o *Orchestrator) runEngine(ctx context.Context, s scanner.Scanner, sc *scanContext, target string, opts scanner.Options, result *ScanResult) {
	if err := s.CheckInstalled(); err != nil {
		result.Err = err
		return
	}

	engineRunID := ulid.Make().String()
	runStarted := time.Now()
	res, err := s.Run(ctx, target, opts)
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

	runStatus := "completed"
	errMsg := (*string)(nil)
	if err != nil {
		runStatus = "failed"
		e := err.Error()
		errMsg = &e
	}

	engineRun, err := o.q.CreateEngineRun(ctx, sqlc.CreateEngineRunParams{
		ID:            engineRunID,
		ScanID:        sc.scanID,
		Engine:        s.Name(),
		Category:      string(s.Category()),
		Command:       cmdStr,
		Status:        runStatus,
		ExitCode:      int64Ptr(exitCode),
		DurationMs:    int64Ptr(durationMs),
		ErrorMessage:  errMsg,
		StartedAt:     &runStarted,
		CompletedAt:   &runCompleted,
	})
	if err != nil {
		result.Err = fmt.Errorf("建立 engine_run 失敗: %w", err)
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
		if _, err := o.q.UpsertFinding(ctx, params); err != nil {
			result.Err = fmt.Errorf("寫入 finding 失敗: %w", err)
			return
		}
		result.Total++
		result.BySeverity[f.Severity]++
		result.ByEngine[s.Name()]++
	}
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
