package sbom

import (
	"reflect"
	"testing"
)

func TestDiffPackages(t *testing.T) {
	from := []Package{
		{Name: "lodash", Version: "4.17.20", Type: "library", PURL: "pkg:npm/lodash@4.17.20"},
		{Name: "left-pad", Version: "1.3.0", Type: "library", PURL: "pkg:npm/left-pad@1.3.0"},
		{Name: "express", Version: "4.18.2", Type: "library", PURL: "pkg:npm/express@4.18.2"},
	}
	to := []Package{
		{Name: "lodash", Version: "4.17.21", Type: "library", PURL: "pkg:npm/lodash@4.17.21"}, // 版本升
		{Name: "express", Version: "4.18.2", Type: "library", PURL: "pkg:npm/express@4.18.2"}, // 不變
		{Name: "axios", Version: "1.6.0", Type: "library", PURL: "pkg:npm/axios@1.6.0"},       // 新增
		// left-pad 移除
	}

	diff := DiffPackages(from, to)

	if len(diff.Added) != 1 || diff.Added[0].Name != "axios" {
		t.Errorf("Added = %+v 預期只有 axios", diff.Added)
	}
	if len(diff.Removed) != 1 || diff.Removed[0].Name != "left-pad" {
		t.Errorf("Removed = %+v 預期只有 left-pad", diff.Removed)
	}
	if len(diff.Changed) != 1 {
		t.Fatalf("Changed = %+v 預期只有 lodash 版本變動", diff.Changed)
	}
	got := diff.Changed[0]
	want := PackageChange{Name: "lodash", Type: "library", PURL: "pkg:npm/lodash@4.17.21", OldVersion: "4.17.20", NewVersion: "4.17.21"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Changed[0] = %+v 預期 %+v", got, want)
	}
	if diff.Unchanged != 1 {
		t.Errorf("Unchanged = %d 預期 1 (express)", diff.Unchanged)
	}
}

/* TestDiffPackagesEmpty 空對空與單邊空 皆回非 nil 空切片 供 JSON 序列化為 [] */
func TestDiffPackagesEmpty(t *testing.T) {
	diff := DiffPackages(nil, nil)
	if diff.Added == nil || diff.Removed == nil || diff.Changed == nil {
		t.Fatalf("空輸入切片不應為 nil: %+v", diff)
	}
	if len(diff.Added)+len(diff.Removed)+len(diff.Changed) != 0 || diff.Unchanged != 0 {
		t.Errorf("空輸入應無任何差異: %+v", diff)
	}

	pkgs := []Package{{Name: "a", Version: "1.0.0", PURL: "pkg:npm/a@1.0.0"}}
	if d := DiffPackages(nil, pkgs); len(d.Added) != 1 {
		t.Errorf("from 空時 to 全為新增: %+v", d)
	}
	if d := DiffPackages(pkgs, nil); len(d.Removed) != 1 {
		t.Errorf("to 空時 from 全為移除: %+v", d)
	}
}

/*
	TestDiffPackagesNoPURL 無 purl 時以 type+name 作 coordinate

同名不同 type 視為不同套件 不誤判為版本變動
*/
func TestDiffPackagesNoPURL(t *testing.T) {
	from := []Package{
		{Name: "openssl", Version: "1.1.1", Type: "os-package"},
		{Name: "openssl", Version: "3.0.0", Type: "library"},
	}
	to := []Package{
		{Name: "openssl", Version: "1.1.2", Type: "os-package"}, // os-package 版本升
		{Name: "openssl", Version: "3.0.0", Type: "library"},    // library 不變
	}

	diff := DiffPackages(from, to)
	if len(diff.Added) != 0 || len(diff.Removed) != 0 {
		t.Errorf("同 coordinate 不應有新增或移除: %+v", diff)
	}
	if len(diff.Changed) != 1 || diff.Changed[0].Type != "os-package" {
		t.Errorf("僅 os-package 版本變動: %+v", diff.Changed)
	}
	if diff.Unchanged != 1 {
		t.Errorf("library 不變: Unchanged = %d", diff.Unchanged)
	}
}

/*
	TestDiffPackagesScopedNotCollapsed 多個 npm scoped 套件不可因 scope 的 @ 坍縮成同一 coordinate

回歸測試 早期以第一個 @ 切版本會把所有 @scope 套件誤判為同一個
*/
func TestDiffPackagesScopedNotCollapsed(t *testing.T) {
	pkgs := []Package{
		{Name: "@babel/core", Version: "7.0.0", Type: "library", PURL: "pkg:npm/@babel/core@7.0.0"},
		{Name: "@babel/parser", Version: "7.0.0", Type: "library", PURL: "pkg:npm/@babel/parser@7.0.0"},
		{Name: "@types/node", Version: "20.0.0", Type: "library", PURL: "pkg:npm/@types/node@20.0.0"},
	}
	/* 三個不同 scoped 套件與自身比較 應全部不變 而非坍縮成 1 個 */
	diff := DiffPackages(pkgs, pkgs)
	if diff.Unchanged != 3 {
		t.Errorf("三個 scoped 套件應各自不變 Unchanged = %d 預期 3", diff.Unchanged)
	}
	if len(diff.Added) != 0 || len(diff.Removed) != 0 || len(diff.Changed) != 0 {
		t.Errorf("同清單比較不應有任何差異: %+v", diff)
	}
}

func TestCoordinateKey(t *testing.T) {
	cases := []struct {
		pkg  Package
		want string
	}{
		{Package{Name: "lodash", Type: "library", PURL: "pkg:npm/lodash@4.17.21"}, "pkg:npm/lodash"},
		{Package{Name: "lodash", Type: "library", PURL: "pkg:npm/lodash"}, "pkg:npm/lodash"},                      // 無版本 purl
		{Package{Name: "openssl", Type: "os-package"}, "os-package|openssl"},                                      // 無 purl 退回 type|name
		{Package{Name: "@babel/core", Type: "library", PURL: "pkg:npm/@babel/core@7.0.0"}, "pkg:npm/@babel/core"}, // scoped 套件 scope 的 @ 不可誤切
		{Package{Name: "@babel/core", Type: "library", PURL: "pkg:npm/@babel/core"}, "pkg:npm/@babel/core"},       // scoped 無版本
		{Package{Name: "lodash", Type: "library", PURL: "pkg:npm/lodash@4.17.21?arch=x64"}, "pkg:npm/lodash"},     // 帶 qualifiers
	}
	for _, c := range cases {
		if got := coordinateKey(c.pkg); got != c.want {
			t.Errorf("coordinateKey(%+v) = %q 預期 %q", c.pkg, got, c.want)
		}
	}
}
