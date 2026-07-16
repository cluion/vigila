package core

import (
	"context"
	"errors"
	"fmt"

	"github.com/cluion/vigila/internal/store/sqlc"
)

/* ErrCrossProject 表示兩次掃描屬不同 project 無法比較 */
var ErrCrossProject = errors.New("不同 project 的掃描無法比較")

/*
	DiffResult 為兩次掃描的差集

以 hash_code 比較 scan_findings 的關聯集合
Added 為 to 有而 from 沒有 Removed 反之 Unchanged 為交集數
*/
type DiffResult struct {
	From      sqlc.Scan
	To        sqlc.Scan
	Added     []sqlc.Finding
	Removed   []sqlc.Finding
	Unchanged int64
}

/* Diff 比較兩次掃描的 findings 差異 兩者需屬同一 project */
func Diff(ctx context.Context, q *sqlc.Queries, fromID, toID string) (*DiffResult, error) {
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

	added, err := q.ListFindingsOnlyInScan(ctx, sqlc.ListFindingsOnlyInScanParams{
		ScanID:   toID,
		ScanID_2: fromID,
	})
	if err != nil {
		return nil, fmt.Errorf("查詢新增 findings 失敗: %w", err)
	}

	removed, err := q.ListFindingsOnlyInScan(ctx, sqlc.ListFindingsOnlyInScanParams{
		ScanID:   fromID,
		ScanID_2: toID,
	})
	if err != nil {
		return nil, fmt.Errorf("查詢消失 findings 失敗: %w", err)
	}

	unchanged, err := q.CountCommonFindings(ctx, sqlc.CountCommonFindingsParams{
		ScanID:   fromID,
		ScanID_2: toID,
	})
	if err != nil {
		return nil, fmt.Errorf("查詢共同 findings 失敗: %w", err)
	}

	return &DiffResult{
		From:      from,
		To:        to,
		Added:     added,
		Removed:   removed,
		Unchanged: unchanged,
	}, nil
}
