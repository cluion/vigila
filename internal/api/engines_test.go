package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/cluion/vigila/internal/core/model"
	"github.com/cluion/vigila/internal/scanner"
)

/* infoStub 為 engineInfos 測試用假引擎 可控制類別 目標型態與安裝狀態 */
type infoStub struct {
	name     string
	cat      model.Category
	kinds    []scanner.TargetKind
	checkErr error
}

func (e *infoStub) Name() string                      { return e.name }
func (e *infoStub) Category() model.Category          { return e.cat }
func (e *infoStub) Binary() string                    { return e.name }
func (e *infoStub) TargetKinds() []scanner.TargetKind { return e.kinds }
func (e *infoStub) CheckInstalled() error             { return e.checkErr }
func (e *infoStub) ExitCodeIsFindings(int) bool       { return false }
func (e *infoStub) Parse([]byte) ([]model.Finding, error) {
	return nil, nil
}
func (e *infoStub) BuildCommand(string, scanner.Options) (string, []string) {
	return e.name, nil
}
func (e *infoStub) Run(context.Context, string, scanner.Options) (*scanner.Result, error) {
	return &scanner.Result{}, nil
}

func TestEngineInfos(t *testing.T) {
	engines := []scanner.Scanner{
		&infoStub{name: "zeta", cat: model.CategoryVA, kinds: []scanner.TargetKind{scanner.TargetHost}, checkErr: errStub},
		&infoStub{name: "alpha", cat: model.CategorySAST, kinds: []scanner.TargetKind{scanner.TargetPath}},
	}

	infos := engineInfos(engines)

	if len(infos) != 2 {
		t.Fatalf("應有 2 筆 實際 %d", len(infos))
	}
	if infos[0].Name != "alpha" || infos[1].Name != "zeta" {
		t.Errorf("應依名稱排序 實際 %s %s", infos[0].Name, infos[1].Name)
	}
	if infos[0].Category != "SAST" {
		t.Errorf("alpha 類別應為 SAST 實際 %s", infos[0].Category)
	}
	if len(infos[0].TargetKinds) != 1 || infos[0].TargetKinds[0] != "path" {
		t.Errorf("alpha 目標型態應為 [path] 實際 %v", infos[0].TargetKinds)
	}
	if !infos[0].Installed {
		t.Error("alpha checkErr 為 nil 應標記已安裝")
	}
	if infos[1].Installed {
		t.Error("zeta checkErr 非 nil 應標記未安裝")
	}
}

func TestListEnginesResponseShape(t *testing.T) {
	srv, _ := newTestServer(t)
	/* 用 host 型態的 probe 避免與其他測試共用全域 registry 時 汙染「無引擎吃 URL」的斷言 */
	scanner.Register(&infoStub{name: "shape-probe", cat: model.CategoryVA, kinds: []scanner.TargetKind{scanner.TargetHost}, checkErr: errStub})

	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/engines", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/api/engines 回應碼 %d", rec.Code)
	}

	var body struct {
		Engines []struct {
			Name        string   `json:"name"`
			Category    string   `json:"category"`
			TargetKinds []string `json:"target_kinds"`
			Installed   bool     `json:"installed"`
		} `json:"engines"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("解析 engines 回應失敗: %v", err)
	}

	var probe *struct {
		Name        string   `json:"name"`
		Category    string   `json:"category"`
		TargetKinds []string `json:"target_kinds"`
		Installed   bool     `json:"installed"`
	}
	for i := range body.Engines {
		if body.Engines[i].Name == "shape-probe" {
			probe = &body.Engines[i]
		}
	}
	if probe == nil {
		t.Fatal("回應應含註冊的 shape-probe 引擎")
	}
	if probe.Category != "VA" {
		t.Errorf("shape-probe 類別應為 VA 實際 %s", probe.Category)
	}
	if len(probe.TargetKinds) != 1 || probe.TargetKinds[0] != "host" {
		t.Errorf("shape-probe 目標型態應為 [host] 實際 %v", probe.TargetKinds)
	}
	if probe.Installed {
		t.Error("shape-probe checkErr 非 nil 應為未安裝")
	}
}

/* errStub 供假引擎模擬未安裝 */
var errStub = &stubError{}

type stubError struct{}

func (*stubError) Error() string { return "未安裝" }
