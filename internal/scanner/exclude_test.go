package scanner

import (
	"reflect"
	"testing"
)

func TestExcludeArgs(t *testing.T) {
	t.Run("每個 pattern 組成一組 flag value", func(t *testing.T) {
		got := ExcludeArgs("--exclude", []string{"node_modules", "vendor"})
		want := []string{"--exclude", "node_modules", "--exclude", "vendor"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("ExcludeArgs = %v 預期 %v", got, want)
		}
	})

	t.Run("空清單回空切片", func(t *testing.T) {
		if got := ExcludeArgs("--skip-dirs", nil); len(got) != 0 {
			t.Errorf("空輸入應回空 實際 %v", got)
		}
	})

	t.Run("防禦性略過以 - 開頭者 避免引數走私", func(t *testing.T) {
		got := ExcludeArgs("--exclude", []string{"vendor", "--output=/etc/x", "-rf"})
		want := []string{"--exclude", "vendor"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("應只保留合法 pattern 實際 %v", got)
		}
	})
}

func TestValidateExcludes(t *testing.T) {
	if err := ValidateExcludes([]string{"vendor", "node_modules", "a/b"}); err != nil {
		t.Errorf("合法 pattern 不應回錯 實際 %v", err)
	}
	for _, bad := range [][]string{{"-rf"}, {"--output=/etc/x"}, {"vendor", "-x"}, {""}} {
		if err := ValidateExcludes(bad); err == nil {
			t.Errorf("非法 pattern %v 應回錯", bad)
		}
	}
}
