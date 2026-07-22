package engine

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseInstallArg(t *testing.T) {
	tests := []struct {
		arg         string
		wantName    string
		wantVersion string
		wantErr     bool
	}{
		{"gitleaks", "gitleaks", "", false},
		{"gitleaks@8.30.1", "gitleaks", "8.30.1", false},
		{"gitleaks@v8.30.1", "gitleaks", "8.30.1", false},
		{"gitleaks@latest", "gitleaks", "latest", false},
		{"gitleaks@", "", "", true},
		{"@8.30.1", "", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.arg, func(t *testing.T) {
			name, version, err := parseInstallArg(tt.arg)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseInstallArg(%q) 應回錯", tt.arg)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseInstallArg(%q) 失敗: %v", tt.arg, err)
			}
			if name != tt.wantName || version != tt.wantVersion {
				t.Errorf("parseInstallArg(%q) = (%q, %q) 預期 (%q, %q)",
					tt.arg, name, version, tt.wantName, tt.wantVersion)
			}
		})
	}
}

func TestLockRoundTrip(t *testing.T) {
	dir := t.TempDir()

	entry := lockEntry{Version: "8.30.1", Pinned: true, SHA256: "abc", SignatureVerified: true}
	if err := writeLockEntry(dir, "gitleaks", entry); err != nil {
		t.Fatalf("寫入 lock 失敗: %v", err)
	}

	got := readLock(dir)
	if got["gitleaks"] != entry {
		t.Errorf("讀回 lock = %+v 預期 %+v", got["gitleaks"], entry)
	}
}

func TestLockPreservesOtherEngines(t *testing.T) {
	dir := t.TempDir()

	if err := writeLockEntry(dir, "gitleaks", lockEntry{Version: "8.30.1", Pinned: true}); err != nil {
		t.Fatal(err)
	}
	if err := writeLockEntry(dir, "trivy", lockEntry{Version: "0.60.0"}); err != nil {
		t.Fatal(err)
	}

	got := readLock(dir)
	if got["gitleaks"].Version != "8.30.1" || !got["gitleaks"].Pinned {
		t.Errorf("gitleaks 項目應保留 得 %+v", got["gitleaks"])
	}
	if got["trivy"].Version != "0.60.0" {
		t.Errorf("trivy 項目應寫入 得 %+v", got["trivy"])
	}
}

func TestReadLockMissingOrCorrupt(t *testing.T) {
	t.Run("檔案不存在回空表", func(t *testing.T) {
		if got := readLock(t.TempDir()); len(got) != 0 {
			t.Errorf("不存在的 lock 應回空表 得 %+v", got)
		}
	})

	t.Run("損毀 JSON 回空表", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, lockFileName), []byte("{broken"), 0o600); err != nil {
			t.Fatal(err)
		}
		if got := readLock(dir); len(got) != 0 {
			t.Errorf("損毀的 lock 應回空表 得 %+v", got)
		}
	})
}
