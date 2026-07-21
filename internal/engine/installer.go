package engine

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/cluion/vigila/internal/scanner"
	"github.com/sigstore/sigstore-go/pkg/root"
)

/* Result 為一次安裝的結果 */
type Result struct {
	Engine  string
	Version string
	Path    string
	/* SignatureVerified 表示 checksums 檔已通過 cosign keyless 簽章驗證 */
	SignatureVerified bool
	/* Warning 為非致命提醒 例如上游未發佈簽章 僅比對 checksum */
	Warning string
}

/*
	Installer 從 GitHub 官方 release 下載引擎 binary 到 managed 目錄

Get 為可注入的下載函式 供測試以假回應替換 生產環境用 httpGet
GOOS GOARCH 可覆寫 供測試指定平台
*/
type Installer struct {
	DestDir string
	GOOS    string
	GOARCH  string
	Get     func(url string) ([]byte, int, error)

	/* TrustedRoot 提供 cosign 簽章驗證的 Sigstore 信任根 nil 時用預設 TUF 取得 供測試覆寫 */
	TrustedRoot trustedRootLoader
	/* SkipSignature 為 true 時略過簽章驗證 僅供測試 生產環境勿設 */
	SkipSignature bool
}

/* NewInstaller 建立寫入 managed 目錄的安裝器 */
func NewInstaller() *Installer {
	return &Installer{
		DestDir:     scanner.ManagedDir(),
		GOOS:        runtime.GOOS,
		GOARCH:      runtime.GOARCH,
		Get:         httpGet,
		TrustedRoot: fetchTrustedRoot,
	}
}

/* ghRelease 為 GitHub release API 需要的欄位 */
type ghRelease struct {
	TagName string `json:"tag_name"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

/*
	Install 自動安裝指定引擎

流程 抓 latest release → 依平台組 asset 名 → 下載 checksums 比對 sha256
→ 解壓取出 binary → 寫入 managed 目錄並賦予執行權限
*/
func (in *Installer) Install(name string) (*Result, error) {
	spec, err := specFor(name)
	if err != nil {
		return nil, err
	}

	rel, err := in.latestRelease(spec.Repo)
	if err != nil {
		return nil, err
	}
	version := strings.TrimPrefix(rel.TagName, "v")

	assetName := spec.Asset(version, in.GOOS, in.GOARCH)
	assetURL, err := findAsset(rel, assetName)
	if err != nil {
		return nil, fmt.Errorf("找不到 %s 的下載檔 %s（可能該平台未提供）", name, assetName)
	}
	checksumsName, checksumsURL, err := findChecksums(rel)
	if err != nil {
		return nil, err
	}

	/* 下載並以官方 checksums 驗證 */
	archive, err := in.download(assetURL)
	if err != nil {
		return nil, err
	}
	checksums, err := in.download(checksumsURL)
	if err != nil {
		return nil, err
	}

	/* 供應鏈 先驗 checksums 的 cosign 簽章（真實性）再比對 archive 的 sha256（完整性） */
	warning, verified, err := in.verifySignature(name, rel, checksumsName, checksums)
	if err != nil {
		return nil, err
	}

	wantSha, err := parseChecksum(checksums, assetName)
	if err != nil {
		return nil, err
	}
	gotSha := sha256Hex(archive)
	if gotSha != wantSha {
		return nil, fmt.Errorf("%s checksum 不符 預期 %s 實際 %s 已中止安裝", name, wantSha, gotSha)
	}

	bin, err := extractBinary(archive, formatFromAsset(assetName), spec.BinName)
	if err != nil {
		return nil, err
	}

	path, err := in.writeBinary(spec.BinName, bin)
	if err != nil {
		return nil, err
	}
	return &Result{Engine: name, Version: version, Path: path, SignatureVerified: verified, Warning: warning}, nil
}

/*
verifySignature 驗證 checksums 檔的 cosign keyless 簽章

上游有簽章的引擎 下載簽章附檔並驗證 失敗即中止安裝（回 error）
上游無簽章的引擎 回警告字串（非 error）維持 checksum-only
回傳 (warning, verified, error)
*/
func (in *Installer) verifySignature(name string, rel *ghRelease, checksumsName string, checksums []byte) (string, bool, error) {
	if !HasSignature(name) {
		return fmt.Sprintf("%s 上游未發佈簽章 僅以 checksum 驗證完整性 無法驗證來源真實性", name), false, nil
	}
	if in.SkipSignature {
		return "", false, nil
	}

	tr, err := in.trustedRoot()
	if err != nil {
		return "", false, fmt.Errorf("取得 Sigstore 信任根失敗: %w", err)
	}

	/* 簽章附檔命名為 <checksums 檔名> 加固定後綴 依實際存在者下載 */
	assets := map[string][]byte{}
	for _, suffix := range []string{".sig", ".pem", ".sigstore.json"} {
		url, e := findAsset(rel, checksumsName+suffix)
		if e != nil {
			continue
		}
		data, e := in.download(url)
		if e != nil {
			return "", false, fmt.Errorf("下載簽章附檔 %s 失敗: %w", checksumsName+suffix, e)
		}
		assets[suffix] = data
	}

	if err := verifyChecksumSignature(tr, name, checksums, assets); err != nil {
		return "", false, fmt.Errorf("%s 簽章驗證失敗 已中止安裝: %w", name, err)
	}
	return "", true, nil
}

/* trustedRoot 取得簽章驗證信任根 未注入時用預設 TUF 取得器 */
func (in *Installer) trustedRoot() (*root.TrustedRoot, error) {
	if in.TrustedRoot != nil {
		return in.TrustedRoot()
	}
	return fetchTrustedRoot()
}

/* latestRelease 取 GitHub latest release */
func (in *Installer) latestRelease(repo string) (*ghRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", repo)
	body, code, err := in.Get(url)
	if err != nil {
		return nil, fmt.Errorf("查詢 %s 最新版本失敗: %w", repo, err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("查詢 %s 最新版本 HTTP %d", repo, code)
	}
	var rel ghRelease
	if err := json.Unmarshal(body, &rel); err != nil {
		return nil, fmt.Errorf("解析 release 失敗: %w", err)
	}
	return &rel, nil
}

/* download 下載 URL 內容 非 200 視為失敗 */
func (in *Installer) download(url string) ([]byte, error) {
	body, code, err := in.Get(url)
	if err != nil {
		return nil, fmt.Errorf("下載失敗 %s: %w", url, err)
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("下載 %s HTTP %d", url, code)
	}
	return body, nil
}

/* writeBinary 寫入 managed 目錄並賦予執行權限 windows 補 .exe 副檔名供 PATH 解析 */
func (in *Installer) writeBinary(binName string, content []byte) (string, error) {
	if in.DestDir == "" {
		return "", fmt.Errorf("managed 目錄未設定")
	}
	/* 0o750 不開放 world managed 目錄僅存放本人下載的引擎 */
	if err := os.MkdirAll(in.DestDir, 0o750); err != nil {
		return "", fmt.Errorf("建立 managed 目錄失敗: %w", err)
	}
	if in.GOOS == "windows" {
		binName += ".exe"
	}
	path := filepath.Join(in.DestDir, binName)
	/* #nosec G306 -- 引擎 binary 需可執行 0o750 已排除 world */
	if err := os.WriteFile(path, content, 0o750); err != nil {
		return "", fmt.Errorf("寫入 binary 失敗: %w", err)
	}
	return path, nil
}

/* findAsset 從 release assets 找出指定名稱的下載連結 */
func findAsset(rel *ghRelease, name string) (string, error) {
	for _, a := range rel.Assets {
		if a.Name == name {
			return a.URL, nil
		}
	}
	return "", fmt.Errorf("release 中找不到 asset %s", name)
}

/*
	findChecksums 找出 release 的官方 checksums 檔 排除簽章附檔

相容 goreleaser 的 checksums.txt 與 osv-scanner 等的 SHA256SUMS 無副檔名
*/
func findChecksums(rel *ghRelease) (string, string, error) {
	for _, a := range rel.Assets {
		n := strings.ToLower(a.Name)
		if strings.HasSuffix(n, ".sig") || strings.HasSuffix(n, ".pem") || strings.HasSuffix(n, ".asc") {
			continue
		}
		isChecksum := (strings.Contains(n, "checksums") && strings.HasSuffix(n, ".txt")) ||
			strings.Contains(n, "sha256sums")
		if isChecksum {
			return a.Name, a.URL, nil
		}
	}
	return "", "", fmt.Errorf("release 中找不到 checksums 檔")
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

/* httpGet 為生產環境的下載實作 */
func httpGet(url string) ([]byte, int, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	return body, resp.StatusCode, err
}
