//go:build integration

package integration

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"

	/* 匿名 import 觸發 SCA adapter 註冊 */
	_ "github.com/cluion/vigila/internal/scanner/grype"
	_ "github.com/cluion/vigila/internal/scanner/trivy"
)

/*
	vulnRequirements 為釘在已知有 CVE 版本的 Python 相依清單

Django/PyYAML/requests 這些版本在 trivy 與 grype 的 DB 皆有大量已知漏洞
供 SCA 引擎穩定偵測 不依賴特定單一 CVE
*/
const vulnRequirements = "Django==2.2.0\nPyYAML==5.1\nrequests==2.19.1\n"

/* writeVulnFixture 寫出含漏洞相依的 requirements.txt 回傳目錄 */
func writeVulnFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "requirements.txt"), []byte(vulnRequirements), 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

/*
	TestTrivyScanEndToEnd 以真實 trivy 掃含漏洞相依的目錄 驗證整條 SCA 路徑

涵蓋 trivy adapter Run（subprocess + JSON stdout）+ core + DB；DB 需已快取（CI 由快取步驟提供）
*/
func TestTrivyScanEndToEnd(t *testing.T) {
	runSCAEngine(t, "trivy")
}

/* TestGrypeScanEndToEnd 以真實 grype 掃含漏洞相依的目錄 驗證整條 SCA 路徑 */
func TestGrypeScanEndToEnd(t *testing.T) {
	runSCAEngine(t, "grype")
}

/*
	runSCAEngine 對指定 SCA 引擎跑端到端掃描並驗證

findings 需 >0、類別為 SCA、至少一筆帶套件名與嚴重度、且真的寫入 DB
*/
func runSCAEngine(t *testing.T, engineName string) {
	orch, q := newOrchestrator(t)
	eng := requireEngine(t, engineName)

	dir := writeVulnFixture(t)

	res, err := orch.RunSingle(context.Background(), eng, dir, scanner.Options{})
	if err != nil {
		t.Fatalf("%s 掃描失敗: %v", engineName, err)
	}
	if res.Total == 0 {
		t.Fatalf("%s 應偵測到漏洞相依 實際 0（skipped=%v）", engineName, res.Skipped)
	}

	n, err := q.CountFindingsByScan(context.Background(), res.ScanID)
	if err != nil {
		t.Fatalf("查詢 scan findings 失敗: %v", err)
	}
	if n == 0 {
		t.Errorf("%s findings 應寫入 DB", engineName)
	}

	/* 抽查 findings 有 SCA 專屬欄位：類別、套件名、嚴重度 */
	findings, err := q.ListFindingsByScan(context.Background(), res.ScanID)
	if err != nil {
		t.Fatalf("列 findings 失敗: %v", err)
	}
	hasPkg := false
	for _, f := range findings {
		if model.Category(f.Category) != model.CategorySCA {
			t.Errorf("%s finding 類別應為 SCA 實際 %s", engineName, f.Category)
		}
		if f.PkgName != nil && *f.PkgName != "" {
			hasPkg = true
		}
	}
	if !hasPkg {
		t.Errorf("%s 應至少一筆 finding 帶套件名", engineName)
	}
}
