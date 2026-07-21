package engine

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
)

/* loadTestRoot 載入 testdata 內固定的 trusted_root.json 讓簽章測試離線且可重現 */
func loadTestRoot(t *testing.T) *root.TrustedRoot {
	t.Helper()
	tr, err := root.NewTrustedRootFromPath(filepath.Join("testdata", "sig", "trusted_root.json"))
	if err != nil {
		t.Fatalf("載入測試信任根失敗: %v", err)
	}
	return tr
}

func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "sig", name))
	if err != nil {
		t.Fatalf("讀取 fixture %s 失敗: %v", name, err)
	}
	return data
}

func TestHasSignature(t *testing.T) {
	signed := []string{"trivy", "grype", "syft", "trufflehog"}
	unsigned := []string{"gitleaks", "nuclei", "osv-scanner", "semgrep"}
	for _, e := range signed {
		if !HasSignature(e) {
			t.Errorf("%s 應有簽章規則", e)
		}
	}
	for _, e := range unsigned {
		if HasSignature(e) {
			t.Errorf("%s 不應有簽章規則", e)
		}
	}
}

/* trivy 的 sigstore bundle 對正確 checksums 應通過完整驗證（tlog/SCT/時戳/憑證鏈/身分） */
func TestVerifyBundleTrivyValid(t *testing.T) {
	tr := loadTestRoot(t)
	checksums := readFixture(t, "trivy_checksums.txt")
	bundle := readFixture(t, "trivy_checksums.txt.sigstore.json")

	err := verifyChecksumSignature(tr, "trivy", checksums, map[string][]byte{
		".sigstore.json": bundle,
	})
	if err != nil {
		t.Fatalf("trivy bundle 驗證應通過 但失敗: %v", err)
	}
}

/* 竄改 checksums 內容後 bundle 驗證應失敗 */
func TestVerifyBundleTrivyTampered(t *testing.T) {
	tr := loadTestRoot(t)
	checksums := append(readFixture(t, "trivy_checksums.txt"), []byte("tampered\n")...)
	bundle := readFixture(t, "trivy_checksums.txt.sigstore.json")

	if err := verifyChecksumSignature(tr, "trivy", checksums, map[string][]byte{".sigstore.json": bundle}); err == nil {
		t.Fatal("竄改 checksums 後 bundle 驗證應失敗")
	}
}

/* grype 的分離式 sig+pem 對正確 checksums 應通過驗證（憑證鏈+身分+簽章） */
func TestVerifyCertBlobGrypeValid(t *testing.T) {
	tr := loadTestRoot(t)
	checksums := readFixture(t, "grype_checksums.txt")
	sig := readFixture(t, "grype_checksums.txt.sig")
	pemData := readFixture(t, "grype_checksums.txt.pem")

	err := verifyChecksumSignature(tr, "grype", checksums, map[string][]byte{
		".sig": sig,
		".pem": pemData,
	})
	if err != nil {
		t.Fatalf("grype sig+pem 驗證應通過 但失敗: %v", err)
	}
}

/* 竄改 checksums 後 ECDSA 簽章驗證應失敗 */
func TestVerifyCertBlobGrypeTampered(t *testing.T) {
	tr := loadTestRoot(t)
	checksums := append(readFixture(t, "grype_checksums.txt"), []byte("tampered\n")...)
	sig := readFixture(t, "grype_checksums.txt.sig")
	pemData := readFixture(t, "grype_checksums.txt.pem")

	if err := verifyChecksumSignature(tr, "grype", checksums, map[string][]byte{".sig": sig, ".pem": pemData}); err == nil {
		t.Fatal("竄改 checksums 後簽章驗證應失敗")
	}
}

/*
以 grype 的合法憑證但套 syft 的身分規則驗證應失敗
證明 SAN 身分釘選有效 攻擊者無法用 A 專案的簽章冒充 B 專案
*/
func TestVerifyCertBlobWrongIdentityRejected(t *testing.T) {
	tr := loadTestRoot(t)
	checksums := readFixture(t, "grype_checksums.txt")
	sig := readFixture(t, "grype_checksums.txt.sig")
	pemData := readFixture(t, "grype_checksums.txt.pem")

	/* 用 syft 的 spec（SAN 釘 anchore/syft）驗 grype（SAN 為 anchore/grype）應被身分檢查擋下 */
	err := verifyCertBlob(tr, sigSpecs["syft"], checksums, sig, pemData)
	if err == nil {
		t.Fatal("grype 憑證套用 syft 身分規則應被拒")
	}
}

/* 缺少簽章附檔應回錯 */
func TestVerifyMissingAssets(t *testing.T) {
	tr := loadTestRoot(t)
	checksums := readFixture(t, "grype_checksums.txt")
	if err := verifyChecksumSignature(tr, "grype", checksums, map[string][]byte{}); err == nil {
		t.Fatal("缺少 sig/pem 應回錯")
	}
	if err := verifyChecksumSignature(tr, "trivy", checksums, map[string][]byte{}); err == nil {
		t.Fatal("缺少 bundle 應回錯")
	}
}

/*
TestInstallSignedEngineIntegration 真實端到端 實跑 TUF 取信任根 + GitHub 下載 + 簽章驗證
需網路 預設略過 以 VIGILA_NET_TEST=1 啟用 驗證整條 managed install 簽章路徑
*/
func TestInstallSignedEngineIntegration(t *testing.T) {
	if os.Getenv("VIGILA_NET_TEST") != "1" {
		t.Skip("設 VIGILA_NET_TEST=1 以啟用真實網路整合測試")
	}
	in := &Installer{
		DestDir:     t.TempDir(),
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
		Get:         httpGet,
		TrustedRoot: fetchTrustedRoot,
	}
	res, err := in.Install("grype")
	if err != nil {
		t.Fatalf("安裝 grype 失敗: %v", err)
	}
	if !res.SignatureVerified {
		t.Fatalf("grype 應通過簽章驗證 但 SignatureVerified=false warning=%q", res.Warning)
	}
	t.Logf("grype %s 簽章已驗證 路徑 %s", res.Version, res.Path)
}
