package sbom

import (
	"encoding/json"
	"strings"
	"testing"
)

/* convertFixture 為含多套件與多授權的 CycloneDX 供轉換測試 */
const convertFixture = `{
  "bomFormat": "CycloneDX",
  "components": [
    {"type":"library","name":"django","version":"2.0.0","purl":"pkg:pypi/django@2.0.0","licenses":[{"license":{"id":"BSD-3-Clause"}}]},
    {"type":"library","name":"flask","version":"0.12.2"}
  ]
}`

/* TestFormatSupported 驗證格式白名單 */
func TestFormatSupported(t *testing.T) {
	for _, f := range []string{"cyclonedx-json", "spdx-json", "syft-json"} {
		if !FormatSupported(f) {
			t.Errorf("%s 應為支援格式", f)
		}
	}
	if FormatSupported("pdf") {
		t.Error("pdf 不應為支援格式")
	}
}

/* TestConvertCycloneDXPassThrough cyclonedx-json 應原樣回傳不轉換 */
func TestConvertCycloneDXPassThrough(t *testing.T) {
	got, err := Convert([]byte(convertFixture), "cyclonedx-json")
	if err != nil {
		t.Fatalf("Convert 失敗: %v", err)
	}
	if string(got) != convertFixture {
		t.Error("cyclonedx-json 應原樣回傳 實際內容已變動")
	}
}

/* TestConvertUnsupportedFormat 不支援格式應回錯 */
func TestConvertUnsupportedFormat(t *testing.T) {
	if _, err := Convert([]byte(convertFixture), "pdf"); err == nil {
		t.Error("不支援格式應回錯")
	}
}

/* TestConvertSPDX 產出應為合法 SPDX 2.2 JSON 含必填欄位 */
func TestConvertSPDX(t *testing.T) {
	got, err := Convert([]byte(convertFixture), "spdx-json")
	if err != nil {
		t.Fatalf("Convert spdx-json 失敗: %v", err)
	}

	var doc spdxDoc
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("SPDX 產出非合法 JSON: %v", err)
	}

	if doc.SPDXVersion != "SPDX-2.2" {
		t.Errorf("spdxVersion = %q 預期 SPDX-2.2", doc.SPDXVersion)
	}
	if doc.DataLicense != "CC0-1.0" {
		t.Errorf("dataLicense = %q 預期 CC0-1.0", doc.DataLicense)
	}
	if doc.SPDXID != "SPDXRef-DOCUMENT" {
		t.Errorf("SPDXID = %q 預期 SPDXRef-DOCUMENT", doc.SPDXID)
	}
	if doc.DocumentNamespace == "" {
		t.Error("documentNamespace 不應為空")
	}
	if len(doc.CreationInfo.Creators) == 0 {
		t.Error("creationInfo.creators 不應為空")
	}
	if doc.CreationInfo.Created == "" {
		t.Error("creationInfo.created 不應為空")
	}

	if len(doc.Packages) != 2 {
		t.Fatalf("套件數 = %d 預期 2", len(doc.Packages))
	}
	p1 := doc.Packages[0]
	if p1.Name != "django" || p1.VersionInfo != "2.0.0" {
		t.Errorf("第一套件 = %+v", p1)
	}
	if !strings.HasPrefix(p1.SPDXID, "SPDXRef-Package-") {
		t.Errorf("SPDXID = %q 應為 SPDXRef-Package-<n>", p1.SPDXID)
	}
	if p1.FilesAnalyzed != false {
		t.Error("filesAnalyzed 應為 false")
	}
	if p1.DownloadLocation != "NOASSERTION" {
		t.Errorf("downloadLocation = %q 預期 NOASSERTION", p1.DownloadLocation)
	}
	/* django 帶 BSD-3-Clause 授權 應出現在 licenseDeclared */
	if p1.LicenseDeclared != "BSD-3-Clause" {
		t.Errorf("django licenseDeclared = %q 預期 BSD-3-Clause", p1.LicenseDeclared)
	}
	/* flask 無授權 應為 NOASSERTION */
	if doc.Packages[1].LicenseDeclared != "NOASSERTION" {
		t.Errorf("flask licenseDeclared = %q 預期 NOASSERTION", doc.Packages[1].LicenseDeclared)
	}
}

/* TestConvertSPDXMultipleLicenses 多授權應以 OR 合併為 SPDX expression */
func TestConvertSPDXMultipleLicenses(t *testing.T) {
	content := `{"bomFormat":"CycloneDX","components":[` +
		`{"type":"library","name":"x","version":"1.0","licenses":[` +
		`{"license":{"id":"MIT"}},{"license":{"id":"Apache-2.0"}}]}]}`
	got, err := Convert([]byte(content), "spdx-json")
	if err != nil {
		t.Fatalf("Convert 失敗: %v", err)
	}
	var doc spdxDoc
	_ = json.Unmarshal(got, &doc)
	if doc.Packages[0].LicenseDeclared != "MIT OR Apache-2.0" {
		t.Errorf("多授權 = %q 預期 MIT OR Apache-2.0", doc.Packages[0].LicenseDeclared)
	}
}

/* TestConvertSyftJSON 產出應為合法 syft JSON 含必要頂層與 artifacts */
func TestConvertSyftJSON(t *testing.T) {
	got, err := Convert([]byte(convertFixture), "syft-json")
	if err != nil {
		t.Fatalf("Convert syft-json 失敗: %v", err)
	}

	var doc syftDoc
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("syft JSON 產出非合法 JSON: %v", err)
	}

	if len(doc.Artifacts) != 2 {
		t.Fatalf("artifacts 數 = %d 預期 2", len(doc.Artifacts))
	}
	a1 := doc.Artifacts[0]
	if a1.Name != "django" || a1.Version != "2.0.0" || a1.Type != "library" {
		t.Errorf("第一 artifact = %+v", a1)
	}
	if a1.PURL != "pkg:pypi/django@2.0.0" {
		t.Errorf("django purl = %q", a1.PURL)
	}
	if len(a1.Licenses) != 1 || a1.Licenses[0] != "BSD-3-Clause" {
		t.Errorf("django licenses = %v 預期 [BSD-3-Clause]", a1.Licenses)
	}
	if doc.Descriptor.Name != "vigila" {
		t.Errorf("descriptor.name = %q 預期 vigila", doc.Descriptor.Name)
	}
	if doc.Schema.Version == "" {
		t.Error("schema.version 不應為空")
	}
}

/* TestConvertSPDXEmpty 套件為空時仍應產出合法 SPDX 文件 */
func TestConvertSPDXEmpty(t *testing.T) {
	content := `{"bomFormat":"CycloneDX","components":[]}`
	got, err := Convert([]byte(content), "spdx-json")
	if err != nil {
		t.Fatalf("空套件 Convert 失敗: %v", err)
	}
	var doc spdxDoc
	if err := json.Unmarshal(got, &doc); err != nil {
		t.Fatalf("空 SPDX 非合法 JSON: %v", err)
	}
	if doc.SPDXVersion != "SPDX-2.2" {
		t.Errorf("空 SPDX version 應仍為 SPDX-2.2 實際 %q", doc.SPDXVersion)
	}
	if len(doc.Packages) != 0 {
		t.Errorf("空 components packages 應為 0 實際 %d", len(doc.Packages))
	}
}
