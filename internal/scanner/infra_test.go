package scanner

import (
	"context"
	"strings"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
)

/* TestDefaultRunCapturesOutput 以 echo 驗證 DefaultRun 捕獲 stdout 與 exit 0 */
func TestDefaultRunCapturesOutput(t *testing.T) {
	res, err := DefaultRun(context.Background(), "echo", []string{"hello-vigila"})
	if err != nil {
		t.Fatalf("DefaultRun echo 失敗: %v", err)
	}
	if !strings.Contains(string(res.RawOutput), "hello-vigila") {
		t.Errorf("應捕獲 stdout 實際 %q", res.RawOutput)
	}
	if res.ExitCode != 0 {
		t.Errorf("echo 應 exit 0 實際 %d", res.ExitCode)
	}
	if res.Command == "" {
		t.Error("Command 應記錄實際指令")
	}
}

/* TestDefaultRunNonZeroExit 以 sh -c exit 3 驗證非零 exit code 擷取 */
func TestDefaultRunNonZeroExit(t *testing.T) {
	res, err := DefaultRun(context.Background(), "sh", []string{"-c", "exit 3"})
	if err != nil {
		t.Fatalf("DefaultRun 非零退出不應回 error（由 ExitCode 表達）: %v", err)
	}
	if res.ExitCode != 3 {
		t.Errorf("exit code 應為 3 實際 %d", res.ExitCode)
	}
}

/* TestDockerReportArgs 純參數組法 含與不含 user */
func TestDockerReportArgs(t *testing.T) {
	withUser := DockerReportArgs("gitleaks", "/abs/t", "/out", "1000", []string{"detect"})
	joined := strings.Join(withUser, " ")
	for _, want := range []string{"--profile gitleaks", "--user 1000", "/abs/t:/abs/t", "/out:/out", "detect"} {
		if !strings.Contains(joined, want) {
			t.Errorf("DockerReportArgs 應含 %q 實際 %s", want, joined)
		}
	}

	noUser := DockerReportArgs("zap", "/abs/t", "/out", "", nil)
	if strings.Contains(strings.Join(noUser, " "), "--user") {
		t.Error("user 為空時不應加 --user")
	}
}

/* TestManagedDirEnvOverride VIGILA_ENGINES_DIR 覆寫 managed 目錄 */
func TestManagedDirEnvOverride(t *testing.T) {
	t.Setenv("VIGILA_ENGINES_DIR", "/custom/engines")
	if ManagedDir() != "/custom/engines" {
		t.Errorf("ManagedDir 應回環境變數值 實際 %q", ManagedDir())
	}
}

/* infraStub 為 registry 測試用最小引擎 */
type infraStub struct{ name string }

func (s infraStub) Name() string              { return s.name }
func (s infraStub) Category() model.Category  { return model.CategorySAST }
func (s infraStub) Binary() string            { return s.name }
func (s infraStub) VersionArgs() []string     { return nil }
func (s infraStub) TargetKinds() []TargetKind { return []TargetKind{TargetPath} }
func (s infraStub) InstallHint() InstallHint  { return InstallHint{} }
func (s infraStub) CheckInstalled() error     { return nil }
func (s infraStub) BuildCommand(string, Options) (string, []string) {
	return s.name, nil
}
func (s infraStub) Run(context.Context, string, Options) (*Result, error) { return &Result{}, nil }
func (s infraStub) Parse([]byte) ([]model.Finding, error)                 { return nil, nil }
func (s infraStub) ExitCodeIsFindings(int) bool                           { return false }

/* TestRegistryRegisterAndList Register 後 All/Names 應含該引擎 */
func TestRegistryRegisterAndList(t *testing.T) {
	Register(infraStub{name: "zzz-infra-stub"})

	found := false
	for _, s := range All() {
		if s.Name() == "zzz-infra-stub" {
			found = true
			break
		}
	}
	if !found {
		t.Error("All 應含已註冊的 zzz-infra-stub")
	}
	if !strings.Contains(Names(), "zzz-infra-stub") {
		t.Errorf("Names 應含 zzz-infra-stub 實際 %s", Names())
	}
}
