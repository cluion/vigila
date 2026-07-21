package engine

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"path/filepath"
	"regexp"
	"sync"
	"time"

	"github.com/cluion/vigila/internal/scanner"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	fulciocert "github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

/*
簽章驗證 供應鏈防護 C6

managed install 除了比對 checksums 的 sha256（完整性）外 另驗證 checksums 檔本身的
cosign keyless 簽章（真實性）確保 checksums 出自該引擎專案的官方 CI 而非被掉包

只有上游確實發佈簽章的引擎可驗 目前 trivy（自帶 tlog 的 sigstore bundle）與
grype/syft/trufflehog（分離式 .sig + .pem）未發佈簽章的引擎維持 checksum-only 並警告
*/

type sigFormat int

const (
	sigBundle   sigFormat = iota // 自帶 tlog 時戳的 .sigstore.json bundle
	sigCertBlob                  // 分離式 .sig + .pem（Fulcio 憑證）
)

/*
signatureSpec 描述引擎 checksums 的簽章驗證規則

oidcIssuer 與 sanRegex 釘選簽署者身分 唯有該 repo 的 GitHub Actions 才能取得符合的 Fulcio 憑證
sanRegex 只釘 repo 與 workflow 路徑 容忍 ref/檔名隨版本變動
*/
type signatureSpec struct {
	format     sigFormat
	oidcIssuer string
	sanRegex   *regexp.Regexp
}

const githubActionsIssuer = "https://token.actions.githubusercontent.com"

/* sigSpecs 為各引擎的簽章驗證規則 未列者表示上游未發佈簽章 */
var sigSpecs = map[string]signatureSpec{
	"trivy": {
		format:     sigBundle,
		oidcIssuer: githubActionsIssuer,
		sanRegex:   regexp.MustCompile(`^https://github\.com/aquasecurity/trivy/\.github/workflows/.+@refs/`),
	},
	"grype": {
		format:     sigCertBlob,
		oidcIssuer: githubActionsIssuer,
		sanRegex:   regexp.MustCompile(`^https://github\.com/anchore/grype/\.github/workflows/.+@refs/`),
	},
	"syft": {
		format:     sigCertBlob,
		oidcIssuer: githubActionsIssuer,
		sanRegex:   regexp.MustCompile(`^https://github\.com/anchore/syft/\.github/workflows/.+@refs/`),
	},
	"trufflehog": {
		format:     sigCertBlob,
		oidcIssuer: githubActionsIssuer,
		sanRegex:   regexp.MustCompile(`^https://github\.com/trufflesecurity/trufflehog/\.github/workflows/.+@refs/`),
	},
}

/* HasSignature 回報引擎的上游 release 是否發佈可驗證的簽章 */
func HasSignature(engine string) bool {
	_, ok := sigSpecs[engine]
	return ok
}

/*
trustedRootLoader 取得 Sigstore public-good 信任根（Fulcio/Rekor/CTFE 金鑰）

經 TUF 安全更新 快取於 managed 目錄 下 7 天內免重抓 首次需網路
以 sync.Once 快取 供 loader 可被測試以本地 trusted_root.json 覆寫
*/
type trustedRootLoader func() (*root.TrustedRoot, error)

var (
	defaultRootOnce sync.Once
	defaultRoot     *root.TrustedRoot
	defaultRootErr  error
)

func fetchTrustedRoot() (*root.TrustedRoot, error) {
	defaultRootOnce.Do(func() {
		opts := tuf.DefaultOptions().
			WithCachePath(filepath.Join(scanner.ManagedDir(), "sigstore-tuf")).
			WithCacheValidity(7)
		defaultRoot, defaultRootErr = root.FetchTrustedRootWithOptions(opts)
	})
	return defaultRoot, defaultRootErr
}

/*
verifyChecksumSignature 驗證 checksums 檔的 cosign keyless 簽章

assets 為簽章附檔內容 依格式取用 bundle 用 .sigstore.json；sigcert 用 .sig 與 .pem
驗證失敗回錯 呼叫端須中止安裝
*/
func verifyChecksumSignature(tr *root.TrustedRoot, engine string, checksums []byte, assets map[string][]byte) error {
	spec, ok := sigSpecs[engine]
	if !ok {
		return fmt.Errorf("引擎 %s 無簽章驗證規則", engine)
	}
	switch spec.format {
	case sigBundle:
		return verifyBundle(tr, spec, checksums, assets[".sigstore.json"])
	case sigCertBlob:
		return verifyCertBlob(tr, spec, checksums, assets[".sig"], assets[".pem"])
	default:
		return fmt.Errorf("引擎 %s 簽章格式未知", engine)
	}
}

/* verifyBundle 驗證自帶 tlog 的 sigstore bundle（trivy）完整檢查 tlog 收錄 SCT 時戳 憑證鏈 簽章 身分 */
func verifyBundle(tr *root.TrustedRoot, spec signatureSpec, checksums, bundleJSON []byte) error {
	if len(bundleJSON) == 0 {
		return fmt.Errorf("缺少 sigstore bundle 檔")
	}
	b := new(bundle.Bundle)
	if err := b.UnmarshalJSON(bundleJSON); err != nil {
		return fmt.Errorf("解析 sigstore bundle 失敗: %w", err)
	}

	certID, err := verify.NewShortCertificateIdentity(spec.oidcIssuer, "", "", spec.sanRegex.String())
	if err != nil {
		return fmt.Errorf("建立身分政策失敗: %w", err)
	}
	verifier, err := verify.NewVerifier(tr,
		verify.WithSignedCertificateTimestamps(1),
		verify.WithTransparencyLog(1),
		verify.WithObserverTimestamps(1),
	)
	if err != nil {
		return fmt.Errorf("建立驗證器失敗: %w", err)
	}
	policy := verify.NewPolicy(verify.WithArtifact(bytes.NewReader(checksums)), verify.WithCertificateIdentity(certID))
	if _, err := verifier.Verify(b, policy); err != nil {
		return fmt.Errorf("bundle 簽章驗證失敗: %w", err)
	}
	return nil
}

/*
verifyCertBlob 驗證分離式 .sig + .pem（grype/syft/trufflehog）

以信任根的 Fulcio CA 驗證憑證鏈 再比對 SAN 與 OIDC issuer 身分 最後驗 ECDSA 簽章
時點取憑證 NotBefore（Fulcio 憑證僅約 10 分鐘有效且無時戳 無法用當下時間驗鏈）
此路徑不查 Rekor 透明日誌 對「下載是否出自官方」的威脅模型已足夠
*/
func verifyCertBlob(tr *root.TrustedRoot, spec signatureSpec, checksums, sigB64, pemData []byte) error {
	if len(sigB64) == 0 || len(pemData) == 0 {
		return fmt.Errorf("缺少 .sig 或 .pem 簽章檔")
	}

	leaf, err := parseLeafCert(pemData)
	if err != nil {
		return err
	}

	/* 憑證鏈 以簽署當下（憑證 NotBefore）為時點驗證是否鏈到 Fulcio root */
	if _, err := verify.VerifyLeafCertificate(leaf.NotBefore.Add(time.Second), leaf, tr); err != nil {
		return fmt.Errorf("憑證無法鏈至 Fulcio 信任根: %w", err)
	}

	/* 身分 SAN 與 OIDC issuer 須符合釘選的 repo release workflow */
	summary, err := fulciocert.SummarizeCertificate(leaf)
	if err != nil {
		return fmt.Errorf("解析憑證身分失敗: %w", err)
	}
	if !spec.sanRegex.MatchString(summary.SubjectAlternativeName) {
		return fmt.Errorf("憑證 SAN %q 不符預期簽署者", summary.SubjectAlternativeName)
	}
	if summary.Extensions.Issuer != spec.oidcIssuer {
		return fmt.Errorf("憑證 OIDC issuer %q 不符預期 %q", summary.Extensions.Issuer, spec.oidcIssuer)
	}

	/* 簽章 cosign 對 sha256(checksums) 簽 ECDSA .sig 為 base64(DER) */
	sig, err := base64.StdEncoding.DecodeString(string(bytes.TrimSpace(sigB64)))
	if err != nil {
		return fmt.Errorf("解碼簽章失敗: %w", err)
	}
	pub, ok := leaf.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("憑證公鑰非 ECDSA 不支援")
	}
	digest := sha256.Sum256(checksums)
	if !ecdsa.VerifyASN1(pub, digest[:], sig) {
		return fmt.Errorf("checksums 簽章驗證失敗 內容可能遭竄改")
	}
	return nil
}

/* parseLeafCert 解析 Fulcio 葉憑證 相容原始 PEM 與 base64 包裹的 PEM（anchore 等） */
func parseLeafCert(pemData []byte) (*x509.Certificate, error) {
	raw := bytes.TrimSpace(pemData)
	if !bytes.HasPrefix(raw, []byte("-----BEGIN")) {
		decoded, err := base64.StdEncoding.DecodeString(string(raw))
		if err != nil {
			return nil, fmt.Errorf("憑證非 PEM 且 base64 解碼失敗: %w", err)
		}
		raw = decoded
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("解析憑證 PEM 失敗")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("解析憑證失敗: %w", err)
	}
	return cert, nil
}
