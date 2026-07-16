package core

import (
	"context"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
	"github.com/cluion/vigila/internal/store/sqlc"
)

/* runFakeScan 以指定 findings 跑一次掃描 回傳 scan id */
func runFakeScan(t *testing.T, orch *Orchestrator, target string, rules []string) string {
	t.Helper()
	findings := make([]model.Finding, 0, len(rules))
	for _, r := range rules {
		findings = append(findings, fakeFinding(r))
	}
	result, err := orch.RunSingle(context.Background(), &fakeScanner{name: "fake", findings: findings}, target, scanner.Options{})
	if err != nil {
		t.Fatalf("RunSingle 失敗: %v", err)
	}
	return result.ScanID
}

/* TestDiffAddedRemovedUnchanged 兩次掃描的差集 新增 消失 不變 都應正確 */
func TestDiffAddedRemovedUnchanged(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)
	orch := New(q)

	/* scan1 發現 A B scan2 發現 A C 預期 新增 C 消失 B 不變 A */
	scan1 := runFakeScan(t, orch, "/tmp/diff-target", []string{"rule-a", "rule-b"})
	scan2 := runFakeScan(t, orch, "/tmp/diff-target", []string{"rule-a", "rule-c"})

	diff, err := Diff(ctx, q, scan1, scan2)
	if err != nil {
		t.Fatalf("Diff 失敗: %v", err)
	}

	if len(diff.Added) != 1 || diff.Added[0].RuleID != "rule-c" {
		t.Errorf("新增應只有 rule-c 實際 %d 筆: %+v", len(diff.Added), ruleIDs(diff.Added))
	}
	if len(diff.Removed) != 1 || diff.Removed[0].RuleID != "rule-b" {
		t.Errorf("消失應只有 rule-b 實際 %d 筆: %+v", len(diff.Removed), ruleIDs(diff.Removed))
	}
	if diff.Unchanged != 1 {
		t.Errorf("不變應為 1 實際 %d", diff.Unchanged)
	}
}

/* ruleIDs 取出 rule_id 清單 供錯誤訊息 */
func ruleIDs(fs []sqlc.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.RuleID)
	}
	return out
}

/* TestDiffRejectsCrossProject 不同 project 的掃描不可比較 */
func TestDiffRejectsCrossProject(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)
	orch := New(q)

	scan1 := runFakeScan(t, orch, "/tmp/project-x", []string{"rule-a"})
	scan2 := runFakeScan(t, orch, "/tmp/project-y", []string{"rule-a"})

	if _, err := Diff(ctx, q, scan1, scan2); err == nil {
		t.Error("跨 project 的 diff 應回傳錯誤")
	}
}

/* TestDiffUnknownScan 不存在的 scan id 應回傳錯誤 */
func TestDiffUnknownScan(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)

	if _, err := Diff(ctx, q, "nope-1", "nope-2"); err == nil {
		t.Error("不存在的 scan 應回傳錯誤")
	}
}
