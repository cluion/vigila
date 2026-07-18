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
)

/* Result 為一次安裝的結果 */
type Result struct {
	Engine  string
	Version string
	Path    string
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
}

/* NewInstaller 建立寫入 managed 目錄的安裝器 */
func NewInstaller() *Installer {
	return &Installer{
		DestDir: scanner.ManagedDir(),
		GOOS:    runtime.GOOS,
		GOARCH:  runtime.GOARCH,
		Get:     httpGet,
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
	checksumsURL, err := findChecksums(rel)
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
	return &Result{Engine: name, Version: version, Path: path}, nil
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
	if err := os.MkdirAll(in.DestDir, 0o755); err != nil {
		return "", fmt.Errorf("建立 managed 目錄失敗: %w", err)
	}
	if in.GOOS == "windows" {
		binName += ".exe"
	}
	path := filepath.Join(in.DestDir, binName)
	if err := os.WriteFile(path, content, 0o755); err != nil {
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

/* findChecksums 找出 release 的官方 checksums.txt 排除簽章附檔 */
func findChecksums(rel *ghRelease) (string, error) {
	for _, a := range rel.Assets {
		if strings.Contains(a.Name, "checksums") && strings.HasSuffix(a.Name, ".txt") {
			return a.URL, nil
		}
	}
	return "", fmt.Errorf("release 中找不到 checksums 檔")
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
