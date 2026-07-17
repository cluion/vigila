package engine

import "testing"

func TestSpecForKnownEngine(t *testing.T) {
	spec, err := specFor("gitleaks")
	if err != nil {
		t.Fatalf("gitleaks 應有 download spec: %v", err)
	}
	if spec.Repo != "gitleaks/gitleaks" {
		t.Errorf("repo = %q 預期 gitleaks/gitleaks", spec.Repo)
	}
	if spec.Format != "tar.gz" {
		t.Errorf("format = %q 預期 tar.gz", spec.Format)
	}

	got := spec.Asset("8.30.1", "darwin", "arm64")
	want := "gitleaks_8.30.1_darwin_arm64.tar.gz"
	if got != want {
		t.Errorf("asset 名 = %q 預期 %q", got, want)
	}
}

func TestSpecForUnsupportedEngine(t *testing.T) {
	/* semgrep 靠 pip nmap 無可攜 binary 皆不支援自動安裝 */
	for _, name := range []string{"semgrep", "nmap", "unknown-xyz"} {
		if _, err := specFor(name); err == nil {
			t.Errorf("%s 不應有 download spec", name)
		}
	}
}
