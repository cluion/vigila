package core

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
	"github.com/cluion/vigila/internal/store"
	"github.com/cluion/vigila/internal/store/sqlc"
)

/* fakeScanner 為測試用引擎 可控制安裝檢查 exit code 與回傳的 findings */
type fakeScanner struct {
	name     string
	checkErr error
	exitCode int
	findings []model.Finding
	ran      bool
}

func (f *fakeScanner) Name() string             { return f.name }
func (f *fakeScanner) Category() model.Category { return model.CategorySAST }
func (f *fakeScanner) Binary() string           { return f.name }
func (f *fakeScanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetPath}
}
func (f *fakeScanner) CheckInstalled() error            { return f.checkErr }
func (f *fakeScanner) ExitCodeIsFindings(code int) bool { return code == 1 }

func (f *fakeScanner) BuildCommand(target string, opts scanner.Options) (string, []string) {
	return f.name, []string{target}
}

func (f *fakeScanner) Run(ctx context.Context, target string, opts scanner.Options) (*scanner.Result, error) {
	f.ran = true
	return &scanner.Result{
		RawOutput: []byte("{}"),
		ExitCode:  f.exitCode,
		Command:   f.name + " " + target,
	}, nil
}

func (f *fakeScanner) Parse(raw []byte) ([]model.Finding, error) {
	return f.findings, nil
}

/* fakeFinding 產生一筆最小可寫入的 finding */
func fakeFinding(rule string) model.Finding {
	f := model.Finding{
		Engine:   "fake",
		Category: model.CategorySAST,
		RuleID:   rule,
		Title:    rule,
		Severity: model.SeverityHigh,
		FilePath: "main.go",
	}
	f.HashCode = Fingerprint(f)
	return f
}

/* openTestDB 開啟暫存 SQLite 回傳 sqlc Queries */
func openTestDB(t *testing.T) *sqlc.Queries {
	t.Helper()
	ctx := context.Background()
	db, err := store.Open(ctx, store.Config{Driver: "sqlite", DSN: filepath.Join(t.TempDir(), "test.db")})
	if err != nil {
		t.Fatalf("開啟測試資料庫失敗: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return sqlc.New(db)
}

/* TestRunSingleDefaultTriggerSourceIsCLI 預設情境 trigger_source 應為 cli */
func TestRunSingleDefaultTriggerSourceIsCLI(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)
	orch := New(q)

	result, err := orch.RunSingle(ctx, &fakeScanner{name: "fake"}, "/tmp/target", scanner.Options{})
	if err != nil {
		t.Fatalf("RunSingle 失敗: %v", err)
	}

	scan, err := q.GetScan(ctx, result.ScanID)
	if err != nil {
		t.Fatalf("查詢 scan 失敗: %v", err)
	}
	if scan.TriggerSource != "cli" {
		t.Errorf("trigger_source 應為 cli 實際為 %s", scan.TriggerSource)
	}
}

/* TestWithTriggerSourceRecordsWeb Web 觸發時 trigger_source 應記為 web */
func TestWithTriggerSourceRecordsWeb(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)
	orch := New(q).WithTriggerSource("web")

	result, err := orch.RunSingle(ctx, &fakeScanner{name: "fake"}, "/tmp/target", scanner.Options{})
	if err != nil {
		t.Fatalf("RunSingle 失敗: %v", err)
	}

	scan, err := q.GetScan(ctx, result.ScanID)
	if err != nil {
		t.Fatalf("查詢 scan 失敗: %v", err)
	}
	if scan.TriggerSource != "web" {
		t.Errorf("trigger_source 應為 web 實際為 %s", scan.TriggerSource)
	}
}

/* TestRunMultipleScanTypeIsMulti --engine all 走 RunMultiple 時 scan_type 應為 multi 而非 profile */
func TestRunMultipleScanTypeIsMulti(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)
	orch := New(q)

	scanners := []scanner.Scanner{&fakeScanner{name: "fake-a"}, &fakeScanner{name: "fake-b"}}
	result, err := orch.RunMultiple(ctx, scanners, "/tmp/target", scanner.Options{})
	if err != nil {
		t.Fatalf("RunMultiple 失敗: %v", err)
	}

	scan, err := q.GetScan(ctx, result.ScanID)
	if err != nil {
		t.Fatalf("查詢 scan 失敗: %v", err)
	}
	if scan.ScanType != "multi" {
		t.Errorf("scan_type 應為 multi 實際為 %s", scan.ScanType)
	}
}

/* TestUnexpectedExitCodeMarksRunFailed 非零且非 findings 慣例的 exit code 應標記 engine_run 失敗 且不寫入 findings */
func TestUnexpectedExitCodeMarksRunFailed(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)
	orch := New(q)

	/* exit 2 非 findings 慣例 exit 1 才是 即使 Parse 能吐出 findings 也不應採信 */
	s := &fakeScanner{name: "fake", exitCode: 2, findings: []model.Finding{fakeFinding("rule-x")}}
	result, err := orch.RunSingle(ctx, s, "/tmp/target", scanner.Options{})
	if err == nil {
		t.Fatal("非預期 exit code 應回傳錯誤")
	}
	if result.Total != 0 {
		t.Errorf("非預期 exit code 不應寫入 findings 實際寫入 %d 筆", result.Total)
	}

	runs, err := q.ListEngineRunsByScan(ctx, result.ScanID)
	if err != nil || len(runs) != 1 {
		t.Fatalf("查詢 engine_runs 失敗: %v 筆數 %d", err, len(runs))
	}
	if runs[0].Status != "failed" {
		t.Errorf("engine_run 狀態應為 failed 實際為 %s", runs[0].Status)
	}
}

/* TestExitCodeOneIsFindingsNotFailure exit 1 為 findings 慣例 應正常寫入 */
func TestExitCodeOneIsFindingsNotFailure(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)
	orch := New(q)

	s := &fakeScanner{name: "fake", exitCode: 1, findings: []model.Finding{fakeFinding("rule-y")}}
	result, err := orch.RunSingle(ctx, s, "/tmp/target", scanner.Options{})
	if err != nil {
		t.Fatalf("exit 1 應視為正常發現: %v", err)
	}
	if result.Total != 1 {
		t.Errorf("應寫入 1 筆 finding 實際 %d", result.Total)
	}
}

/* TestFailFastStopsRemainingEngines FailFast 開啟時 引擎失敗應中斷後續引擎 */
func TestFailFastStopsRemainingEngines(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)

	for _, tc := range []struct {
		name          string
		failFast      bool
		wantSecondRan bool
	}{
		{name: "failfast 開啟 第二個引擎不執行", failFast: true, wantSecondRan: false},
		{name: "failfast 關閉 第二個引擎照常執行", failFast: false, wantSecondRan: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			orch := New(q)
			broken := &fakeScanner{name: "broken", checkErr: errors.New("未安裝")}
			second := &fakeScanner{name: "second"}

			sc, err := orch.beginScan(ctx, "/tmp/target", "profile", "test-ff", tc.failFast)
			if err != nil {
				t.Fatalf("beginScan 失敗: %v", err)
			}
			opts := map[string]scanner.Options{"broken": {}, "second": {}}
			_, _ = orch.runAndFinish(ctx, sc, []scanner.Scanner{broken, second}, "/tmp/target", opts)

			if second.ran != tc.wantSecondRan {
				t.Errorf("第二個引擎 ran=%v 預期 %v", second.ran, tc.wantSecondRan)
			}
		})
	}
}

/* TestRunProfilePassesFailFast RunProfile 應把 profile 的 FailFast 傳進執行流程 */
func TestRunProfilePassesFailFast(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)

	broken := &fakeScanner{name: "ff-broken", checkErr: errors.New("未安裝")}
	second := &fakeScanner{name: "ff-second"}
	scanner.Register(broken)
	scanner.Register(second)

	builtinProfiles["test-failfast"] = Profile{
		Name:     "test-failfast",
		Engines:  []string{"ff-broken", "ff-second"},
		FailFast: true,
	}
	t.Cleanup(func() { delete(builtinProfiles, "test-failfast") })

	orch := New(q)
	_, err := orch.RunProfile(ctx, "test-failfast", "/tmp/target", scanner.Options{})
	if err == nil {
		t.Fatal("首引擎失敗應回傳錯誤")
	}
	if second.ran {
		t.Error("FailFast profile 首引擎失敗後 不應執行第二個引擎")
	}
}
