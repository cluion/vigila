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
}
