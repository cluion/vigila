package cli

import (
	"bytes"
	"strings"
	"testing"
)

/*
	TestExecutePrintsErrorOnce 錯誤訊息只應印一次

cobra 預設會自己印 Error: 若 Execute 再印一次 使用者會看到重複的訊息
*/
func TestExecutePrintsErrorOnce(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"scan"}) /* scan 需要一個 target 參數 這裡故意不給 */

	var out bytes.Buffer
	code := execute(cmd, &out)

	if code != 1 {
		t.Errorf("失敗的命令應回傳 exit code 1 實際 %d", code)
	}

	got := out.String()
	if n := strings.Count(got, "accepts 1 arg"); n != 1 {
		t.Errorf("錯誤訊息應只印 1 次 實際 %d 次\n輸出:\n%s", n, got)
	}
	if !strings.Contains(got, "錯誤:") {
		t.Errorf("錯誤訊息應有中文前綴 實際輸出:\n%s", got)
	}
}

/* TestExecuteSuccessIsQuiet 成功的命令不應印錯誤 且回傳 0 */
func TestExecuteSuccessIsQuiet(t *testing.T) {
	cmd := NewRootCmd()
	cmd.SetArgs([]string{"version"})

	var out bytes.Buffer
	code := execute(cmd, &out)

	if code != 0 {
		t.Errorf("成功的命令應回傳 exit code 0 實際 %d", code)
	}
	if strings.Contains(out.String(), "錯誤:") {
		t.Errorf("成功的命令不應印錯誤 實際輸出:\n%s", out.String())
	}
}
