package sbom

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
)

/*
	SupportedFormats 為 sbom export 支援的格式清單

cyclonedx-json 為 syft 產生時的原始格式 其餘由 ParsePackages 中介轉換
*/
var SupportedFormats = []string{"cyclonedx-json", "spdx-json", "syft-json"}

/* FormatSupported 回報格式是否支援匯出 */
func FormatSupported(format string) bool {
	for _, f := range SupportedFormats {
		if f == format {
			return true
		}
	}
	return false
}

/*
	Convert 把 CycloneDX 內容轉為目標格式

cyclonedx-json 原樣回傳（存的即此格式 無需轉換）
spdx-json / syft-json 先 ParsePackages 取套件清單 再序列化為目標格式
只保留套件清單層級 轉換後不含 syft 原始的中繼資料（檔案位置 CPE 等）
*/
func Convert(cycloneDXContent []byte, targetFormat string) ([]byte, error) {
	if targetFormat == "cyclonedx-json" {
		return cycloneDXContent, nil
	}

	pkgs, err := ParsePackages(cycloneDXContent)
	if err != nil {
		return nil, err
	}

	switch targetFormat {
	case "spdx-json":
		return toSPDX(pkgs)
	case "syft-json":
		return toSyftJSON(pkgs)
	default:
		return nil, fmt.Errorf("不支援的格式 %s 支援 %s", targetFormat, strings.Join(SupportedFormats, " "))
	}
}

/* ---- SPDX 2.2 JSON ---- */

/*
	spdxDoc 為 SPDX 2.2 JSON 文件結構 含必填欄位

filesAnalyzed=false 時免提供 PackageVerificationCode 與 licenseInfoFromFiles
licenseConcluded / licenseDeclared 未知用 NOASSERTION
*/
type spdxDoc struct {
	SPDXVersion       string      `json:"spdxVersion"`
	DataLicense       string      `json:"dataLicense"`
	SPDXID            string      `json:"SPDXID"`
	Name              string      `json:"name"`
	DocumentNamespace string      `json:"documentNamespace"`
	CreationInfo      spdxCreator `json:"creationInfo"`
	Packages          []spdxPkg   `json:"packages"`
}

type spdxCreator struct {
	Creators []string `json:"creators"`
	Created  string   `json:"created"`
}

type spdxPkg struct {
	Name             string `json:"name"`
	SPDXID           string `json:"SPDXID"`
	VersionInfo      string `json:"versionInfo"`
	DownloadLocation string `json:"downloadLocation"`
	FilesAnalyzed    bool   `json:"filesAnalyzed"`
	LicenseConcluded string `json:"licenseConcluded"`
	LicenseDeclared  string `json:"licenseDeclared"`
	CopyrightText    string `json:"copyrightText"`
}

/*
	toSPDX 把套件清單序列化為 SPDX 2.2 JSON

每個套件 SPDXID 為 SPDXRef-Package-<n> downloadLocation 與授權未知用 NOASSERTION
filesAnalyzed=false 簡化義務 不需提供檔案層級資訊
documentNamespace 帶 UUID 確保跨文件唯一
*/
func toSPDX(pkgs []Package) ([]byte, error) {
	doc := spdxDoc{
		SPDXVersion:       "SPDX-2.2",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "vigila-sbom",
		DocumentNamespace: "https://vigila.dev/spdxdocs/" + uuid.NewString(),
		CreationInfo: spdxCreator{
			Creators: []string{"Tool: vigila"},
			Created:  time.Now().UTC().Format(time.RFC3339),
		},
		Packages: make([]spdxPkg, 0, len(pkgs)),
	}

	for i, p := range pkgs {
		licenseExpr := "NOASSERTION"
		if len(p.Licenses) > 0 {
			/* 多授權以 SPDX OR 表達式合併 供消費者自行詮釋 */
			licenseExpr = strings.Join(p.Licenses, " OR ")
		}
		doc.Packages = append(doc.Packages, spdxPkg{
			Name:             p.Name,
			SPDXID:           fmt.Sprintf("SPDXRef-Package-%d", i+1),
			VersionInfo:      p.Version,
			DownloadLocation: "NOASSERTION",
			FilesAnalyzed:    false,
			LicenseConcluded: licenseExpr,
			LicenseDeclared:  licenseExpr,
			CopyrightText:    "NOASSERTION",
		})
	}

	return json.MarshalIndent(doc, "", "  ")
}

/* ---- syft JSON ---- */

/*
	syftDoc 為 syft JSON 輸出結構 含必要頂層欄位

artifacts 為套件清單 source/descriptor/schema 提供基本中繼資料
locations cpes metadata 等選填欄位省略 syft 與 Dependency-Track 能讀
*/
type syftDoc struct {
	Artifacts  []syftArtifact `json:"artifacts"`
	Source     syftSource     `json:"source"`
	Descriptor syftDescriptor `json:"descriptor"`
	Schema     syftSchema     `json:"schema"`
}

type syftArtifact struct {
	ID        string         `json:"id"`
	Name      string         `json:"name"`
	Version   string         `json:"version"`
	Type      string         `json:"type"`
	PURL      string         `json:"purl"`
	Licenses  []string       `json:"licenses"`
	Locations []syftLocation `json:"locations"`
}

type syftLocation struct {
	Path string `json:"path"`
}

type syftSource struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

type syftDescriptor struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type syftSchema struct {
	Version string `json:"version"`
}

/*
	toSyftJSON 把套件清單序列化為 syft JSON

id 以序號填入 避免 nil UUID 複雜度 type 直接帶入來源的 CycloneDX type
location 留空陣列 syft 與消費者容忍省略
*/
func toSyftJSON(pkgs []Package) ([]byte, error) {
	doc := syftDoc{
		Artifacts: make([]syftArtifact, 0, len(pkgs)),
		Source:    syftSource{Type: "unknown"},
		Descriptor: syftDescriptor{
			Name:    "vigila",
			Version: "1.0",
		},
		Schema: syftSchema{Version: "1.0.0"},
	}

	for i, p := range pkgs {
		doc.Artifacts = append(doc.Artifacts, syftArtifact{
			ID:        fmt.Sprintf("%d", i+1),
			Name:      p.Name,
			Version:   p.Version,
			Type:      p.Type,
			PURL:      p.PURL,
			Licenses:  p.Licenses,
			Locations: []syftLocation{},
		})
	}

	return json.MarshalIndent(doc, "", "  ")
}
