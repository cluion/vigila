package core

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/cluion/vigila/internal/sbom"
	"github.com/cluion/vigila/internal/store/sqlc"
)

/*
	SBOMDiffResult 為兩次掃描 SBOM 的比較結果

Diff 為套件層級差異 FromTotal ToTotal 為各自套件總數 供摘要顯示
*/
type SBOMDiffResult struct {
	From      sqlc.Scan
	To        sqlc.Scan
	FromTotal int
	ToTotal   int
	Diff      sbom.Diff
}

/*
	DiffSBOM 比較兩次掃描產生的 SBOM 差異 from 為舊 to 為新

兩次掃描需屬同一 project 各自需已產生 SBOM artifact 缺一即回明確錯誤
*/
func DiffSBOM(ctx context.Context, q *sqlc.Queries, fromID, toID string) (*SBOMDiffResult, error) {
	from, err := q.GetScan(ctx, fromID)
	if err != nil {
		return nil, fmt.Errorf("找不到 scan %s: %w", fromID, err)
	}
	to, err := q.GetScan(ctx, toID)
	if err != nil {
		return nil, fmt.Errorf("找不到 scan %s: %w", toID, err)
	}
	if from.ProjectID != to.ProjectID {
		return nil, fmt.Errorf("scan %s 與 %s: %w", fromID, toID, ErrCrossProject)
	}

	fromPkgs, err := loadSBOMPackages(ctx, q, fromID)
	if err != nil {
		return nil, err
	}
	toPkgs, err := loadSBOMPackages(ctx, q, toID)
	if err != nil {
		return nil, err
	}

	return &SBOMDiffResult{
		From:      from,
		To:        to,
		FromTotal: len(fromPkgs),
		ToTotal:   len(toPkgs),
		Diff:      sbom.DiffPackages(fromPkgs, toPkgs),
	}, nil
}

/* loadSBOMPackages 取出 scan 最新 SBOM 並解析為套件清單 無 SBOM 回引導錯誤 */
func loadSBOMPackages(ctx context.Context, q *sqlc.Queries, scanID string) ([]sbom.Package, error) {
	art, err := q.GetLatestSBOMByScan(ctx, scanID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("scan %s: %w", scanID, ErrNoSBOM)
		}
		return nil, fmt.Errorf("查詢 SBOM 失敗: %w", err)
	}
	pkgs, err := sbom.ParsePackages([]byte(art.Content))
	if err != nil {
		return nil, fmt.Errorf("解析 scan %s 的 SBOM 失敗: %w", scanID, err)
	}
	return pkgs, nil
}
