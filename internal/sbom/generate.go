package sbom

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"

	"github.com/cluion/vigila/internal/scanner"
)

/* Binary 為 SBOM 產生器引擎名 供安裝指引與 managed 解析共用 */
const Binary = "syft"

/* Format 為本輪產出的 SBOM 格式 CycloneDX JSON 業界通用 OWASP 標準 */
const Format = "cyclonedx-json"

/* syftArgs 組出 syft 產 CycloneDX JSON 的參數 */
func syftArgs(target string) []string {
	return []string{"scan", target, "-o", Format}
}

/*
	Generate 對目標執行 syft 產出 CycloneDX JSON

binary 解析沿用 scanner managed 優先於 PATH syft 未安裝時回錯
只捕獲 stdout syft 進度訊息走 stderr 不混入 SBOM
*/
func Generate(ctx context.Context, target string) ([]byte, error) {
	if err := scanner.CheckBinary(Binary); err != nil {
		return nil, err
	}

	cmd := exec.CommandContext(ctx, scanner.ResolveBinary(Binary), syftArgs(target)...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("syft 執行失敗: %w: %s", err, stderr.String())
	}
	return stdout.Bytes(), nil
}
