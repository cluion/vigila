package sbom

import "testing"

const sampleCycloneDX = `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.7",
  "components": [
    {
      "type": "library",
      "name": "django",
      "version": "2.0.0",
      "purl": "pkg:pypi/django@2.0.0"
    },
    {
      "type": "library",
      "name": "flask",
      "version": "0.12.2",
      "purl": "pkg:pypi/flask@0.12.2",
      "licenses": [{"license": {"id": "BSD-3-Clause"}}]
    },
    {
      "type": "library",
      "name": "requests",
      "version": "2.20.0",
      "licenses": [{"expression": "Apache-2.0"}]
    }
  ]
}`

func TestParsePackages(t *testing.T) {
	pkgs, err := ParsePackages([]byte(sampleCycloneDX))
	if err != nil {
		t.Fatalf("解析失敗: %v", err)
	}
	if len(pkgs) != 3 {
		t.Fatalf("套件數 = %d 預期 3", len(pkgs))
	}

	if pkgs[0].Name != "django" || pkgs[0].Version != "2.0.0" || pkgs[0].Type != "library" {
		t.Errorf("第一個套件 = %+v", pkgs[0])
	}
	if pkgs[0].PURL != "pkg:pypi/django@2.0.0" {
		t.Errorf("django purl = %q", pkgs[0].PURL)
	}
	if len(pkgs[0].Licenses) != 0 {
		t.Errorf("django 無授權 應為空 實際 %v", pkgs[0].Licenses)
	}

	/* license.id 形式 */
	if len(pkgs[1].Licenses) != 1 || pkgs[1].Licenses[0] != "BSD-3-Clause" {
		t.Errorf("flask 授權 = %v 預期 [BSD-3-Clause]", pkgs[1].Licenses)
	}
	/* expression 形式 */
	if len(pkgs[2].Licenses) != 1 || pkgs[2].Licenses[0] != "Apache-2.0" {
		t.Errorf("requests 授權 = %v 預期 [Apache-2.0]", pkgs[2].Licenses)
	}
}

func TestParsePackagesEmpty(t *testing.T) {
	pkgs, err := ParsePackages([]byte(`{"bomFormat":"CycloneDX","components":[]}`))
	if err != nil {
		t.Fatalf("空 components 不應報錯: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("應為空 實際 %d", len(pkgs))
	}
}

func TestParsePackagesInvalid(t *testing.T) {
	if _, err := ParsePackages([]byte("not json")); err == nil {
		t.Error("非 JSON 應報錯")
	}
}

func TestSyftArgs(t *testing.T) {
	got := syftArgs("./myapp")
	want := []string{"scan", "./myapp", "-o", "cyclonedx-json"}
	if len(got) != len(want) {
		t.Fatalf("syftArgs = %v 預期 %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("syftArgs[%d] = %q 預期 %q", i, got[i], want[i])
		}
	}
}
