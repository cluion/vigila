package scanner

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"
	"time"
)

/*
	DefaultRun 以 subprocess 執行引擎 並捕獲 stdout

多數引擎共用此實作 Gitleaks 等只能寫檔的引擎另行覆寫
*/
func DefaultRun(ctx context.Context, binary string, args []string) (*Result, error) {
	start := time.Now()
	/* managed 優先解析實際執行路徑 Command 仍記原名保持顯示乾淨 */
	cmd := exec.CommandContext(ctx, ResolveBinary(binary), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)
	code := exitCode(err)

	return &Result{
		RawOutput:  stdout.Bytes(),
		ExitCode:   code,
		DurationMs: duration.Milliseconds(),
		Command:    strings.Join(append([]string{binary}, args...), " "),
	}, nil
}

/* exitCode 從 exec 的 error 取出 exit code 無 error 為 0 */
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
