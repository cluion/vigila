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
func (f *fakeScanner) VersionArgs() []string    { return []string{"--version"} }
func (f *fakeScanner) TargetKinds() []scanner.TargetKind {
	return []scanner.TargetKind{scanner.TargetPath}
}
func (f *fakeScanner) InstallHint() scanner.InstallHint {
	return scanner.InstallHint{DocsURL: "https://example.com", Command: "install " + f.name}
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
			/* exit code 2 非 findings 慣例 視為真正執行失敗 觸發 fail-fast
			   未安裝的引擎現在會被略過而非視為失敗 見 TestUninstalledEngineSkipped */
			broken := &fakeScanner{name: "broken", exitCode: 2}
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

	broken := &fakeScanner{name: "ff-broken", exitCode: 2}
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

/*
	TestUninstalledEngineSkipped 多引擎掃描中 未安裝的引擎應被略過而非使整場 scan 失敗

已裝引擎的 findings 仍寫入 scan 狀態為 completed 未裝引擎記為 skipped 的 engine_run
*/
func TestUninstalledEngineSkipped(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)
	orch := New(q)

	missing := &fakeScanner{name: "missing", checkErr: errors.New("未安裝")}
	ok := &fakeScanner{name: "ok", findings: []model.Finding{fakeFinding("rule-ok")}}

	sc, err := orch.beginScan(ctx, "/tmp/target", "multi", "", false)
	if err != nil {
		t.Fatalf("beginScan 失敗: %v", err)
	}
	opts := map[string]scanner.Options{"missing": {}, "ok": {}}
	result, runErr := orch.runAndFinish(ctx, sc, []scanner.Scanner{missing, ok}, "/tmp/target", opts)
	if runErr != nil {
		t.Fatalf("有一個引擎成功時 掃描不應回錯: %v", runErr)
	}

	scan, err := q.GetScan(ctx, result.ScanID)
	if err != nil {
		t.Fatalf("查詢 scan 失敗: %v", err)
	}
	if scan.Status != "completed" {
		t.Errorf("掃描狀態應為 completed 實際為 %s", scan.Status)
	}
	if result.Total != 1 {
		t.Errorf("已裝引擎的 finding 應寫入 實際 Total=%d", result.Total)
	}
	if len(result.Skipped) != 1 || result.Skipped[0] != "missing" {
		t.Errorf("未裝引擎應記於 Skipped 實際 %v", result.Skipped)
	}

	runs, err := q.ListEngineRunsByScan(ctx, result.ScanID)
	if err != nil {
		t.Fatalf("查詢 engine_runs 失敗: %v", err)
	}
	var skipped, completed int
	for _, r := range runs {
		switch r.Status {
		case "skipped":
			skipped++
		case "completed":
			completed++
		}
	}
	if skipped != 1 || completed != 1 {
		t.Errorf("應有 1 skipped 與 1 completed engine_run 實際 skipped=%d completed=%d", skipped, completed)
	}
}

/*
TestAllEnginesUninstalledFails 所有引擎皆未安裝時 掃描無一執行 應標為 failed
*/
func TestAllEnginesUninstalledFails(t *testing.T) {
	ctx := context.Background()
	q := openTestDB(t)
	orch := New(q)

	a := &fakeScanner{name: "a", checkErr: errors.New("未安裝")}
	b := &fakeScanner{name: "b", checkErr: errors.New("未安裝")}

	sc, err := orch.beginScan(ctx, "/tmp/target", "multi", "", false)
	if err != nil {
		t.Fatalf("beginScan 失敗: %v", err)
	}
	opts := map[string]scanner.Options{"a": {}, "b": {}}
	result, runErr := orch.runAndFinish(ctx, sc, []scanner.Scanner{a, b}, "/tmp/target", opts)
	if runErr == nil {
		t.Fatal("所有引擎皆未安裝 應回錯")
	}

	scan, err := q.GetScan(ctx, result.ScanID)
	if err != nil {
		t.Fatalf("查詢 scan 失敗: %v", err)
	}
	if scan.Status != "failed" {
		t.Errorf("掃描狀態應為 failed 實際為 %s", scan.Status)
	}
}

/* TestRunSBOMOnlyRejectsNonPath URL host 目標不適用 SBOM 應直接回錯不建立 scan */
func TestRunSBOMOnlyRejectsNonPath(t *testing.T) {
	q := openTestDB(t)
	o := New(q)
	for _, target := range []string{"https://example.com", "scanme.nmap.org:443"} {
		if _, err := o.RunSBOMOnly(context.Background(), target); err == nil {
			t.Errorf("非路徑目標 %s 應回錯", target)
		}
	}
}
