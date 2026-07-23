package zap

import "testing"

/* TestScannerMetadataAccessors 覆蓋介面 metadata 方法 確保不回空且不 panic */
func TestScannerMetadataAccessors(t *testing.T) {
	s := &Scanner{}
	if s.Name() == "" {
		t.Error("Name 不應為空")
	}
	if s.Binary() == "" {
		t.Error("Binary 不應為空")
	}
	if s.Category() == "" {
		t.Error("Category 不應為空")
	}
	if len(s.TargetKinds()) == 0 {
		t.Error("TargetKinds 不應為空")
	}
	hint := s.InstallHint()
	if hint.DocsURL == "" && hint.Command == "" {
		t.Error("InstallHint 應至少有文件或指令")
	}
	_ = s.VersionArgs()
	_ = s.ExitCodeIsFindings(0)
	_ = s.CheckInstalled()
}
