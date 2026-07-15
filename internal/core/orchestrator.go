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

/* Orchestrator 協調單一引擎掃描的完整流程 */
type Orchestrator struct {
	q *sqlc.Queries
}

/* New 建立 Orchestrator 需傳入 sqlc Queries */
func New(q *sqlc.Queries) *Orchestrator {
	return &Orchestrator{q: q}
}

/* ScanResult 是單次掃描的彙整結果 */
type ScanResult struct {
	ScanID    string
	Engine    string
	Category  model.Category
	Total     int
	BySeverity map[model.Severity]int
	DurationMs int64
	Err       error
}

/* RunSingle 執行單一引擎掃描 完整流程

步驟 建立 project 建立 scan 狀態 running 執行引擎 parse findings 寫入 DB 更新 scan 狀態 */
func (o *Orchestrator) RunSingle(ctx context.Context, s scanner.Scanner, target string, opts scanner.Options) (*ScanResult, error) {
	/* 確認引擎已安裝 */
	if err := s.CheckInstalled(); err != nil {
		return nil, err
	}

	/* 建立 project 以 target 目錄名為名 */
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

	/* 建立 scan 狀態 running */
	now := time.Now()
	scanID := ulid.Make().String()
	scan, err := o.q.CreateScan(ctx, sqlc.CreateScanParams{
		ID:            scanID,
		ProjectID:     project.ID,
		Target:        target,
		ScanType:      "single",
		Status:        "running",
		TriggerSource: "cli",
	})
	if err != nil {
		return nil, fmt.Errorf("建立 scan 失敗: %w", err)
	}

	/* 更新最終狀態的 defer */
	result := &ScanResult{
		ScanID:   scan.ID,
		Engine:   s.Name(),
		Category: s.Category(),
		BySeverity: map[model.Severity]int{},
	}
	defer func() {
		completed := time.Now()
		status := "completed"
		if result.Err != nil {
			status = "failed"
		}
		_, _ = o.q.UpdateScanStatus(ctx, sqlc.UpdateScanStatusParams{
			ID:         scan.ID,
			Status:     status,
			StartedAt:  &now,
			CompletedAt: &completed,
		})
	}()

	/* 建立 engine run 紀錄 */
	engineRunID := ulid.Make().String()
	runStarted := time.Now()

	/* 執行引擎 */
	res, err := s.Run(ctx, target, opts)
	runCompleted := time.Now()
	durationMs := int64(0)
	exitCode := int(-1)
	var cmdStr *string
	if res != nil {
		durationMs = res.DurationMs
		exitCode = res.ExitCode
		cs := res.Command
		cmdStr = &cs
	}

	runStatus := "completed"
	errMsg := (*string)(nil)
	if err != nil {
		runStatus = "failed"
		e := err.Error()
		errMsg = &e
		result.Err = err
	}

	engineRun, err := o.q.CreateEngineRun(ctx, sqlc.CreateEngineRunParams{
		ID:            engineRunID,
		ScanID:        scan.ID,
		Engine:        s.Name(),
		Category:      string(s.Category()),
		Command:       cmdStr,
		Status:        runStatus,
		ExitCode:      int64Ptr(int64(exitCode)),
		DurationMs:    int64Ptr(durationMs),
		ErrorMessage:  errMsg,
		StartedAt:     &runStarted,
		CompletedAt:   &runCompleted,
	})
	if err != nil {
		result.Err = fmt.Errorf("建立 engine_run 失敗: %w", err)
		return result, result.Err
	}

	if res == nil {
		return result, result.Err
	}

	/* parse findings */
	findings, perr := s.Parse(res.RawOutput)
	if perr != nil {
		result.Err = fmt.Errorf("parse 引擎輸出失敗: %w", perr)
		return result, result.Err
	}

	/* 寫入 DB 並統計 */
	for _, f := range findings {
		params := toUpsertParams(f, project.ID, scan.ID, engineRun.ID)
		if _, err := o.q.UpsertFinding(ctx, params); err != nil {
			return result, fmt.Errorf("寫入 finding 失敗: %w", err)
		}
		result.Total++
		result.BySeverity[f.Severity]++
	}
	result.DurationMs = durationMs

	return result, nil
}

/* toUpsertParams 將 model.Finding 轉為 sqlc UpsertFindingParams */
func toUpsertParams(f model.Finding, projectID, scanID, engineRunID string) sqlc.UpsertFindingParams {
	p := sqlc.UpsertFindingParams{
		ID:              ulid.Make().String(),
		ProjectID:       projectID,
		ScanID:          scanID,
		EngineRunID:     engineRunID,
		Engine:          f.Engine,
		Category:        string(f.Category),
		RuleID:          f.RuleID,
		Title:           f.Title,
		Severity:        string(f.Severity),
		HashCode:        f.HashCode,
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

/* int64Ptr 將 int 轉為 int64 指標 */
func int64Ptr(v int64) *int64 {
	if v < 0 {
		return nil
	}
	return &v
}
