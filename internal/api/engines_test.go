package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
func (e *infoStub) VersionArgs() []string             { return []string{"--version"} }
func (e *infoStub) TargetKinds() []scanner.TargetKind { return e.kinds }
func (e *infoStub) InstallHint() scanner.InstallHint {
	return scanner.InstallHint{DocsURL: "https://example.com", Command: "install " + e.name}
}
func (e *infoStub) CheckInstalled() error       { return e.checkErr }
func (e *infoStub) ExitCodeIsFindings(int) bool { return false }
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
	/* stub 的 binary 名不在 PATH 也不在 managed 來源皆為 missing 版本應留空 */
	for _, info := range infos {
		if info.Source != "missing" {
			t.Errorf("引擎 %s 來源應為 missing 實際 %s", info.Name, info.Source)
		}
		if info.Installed {
			t.Errorf("引擎 %s 不在任何來源 不應標記已安裝", info.Name)
		}
		if info.Version != "" {
			t.Errorf("引擎 %s 未安裝版本應留空 實際 %s", info.Name, info.Version)
		}
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

	type engineJSON struct {
		Name        string   `json:"name"`
		Category    string   `json:"category"`
		TargetKinds []string `json:"target_kinds"`
		Installed   bool     `json:"installed"`
		Version     string   `json:"version"`
		Source      string   `json:"source"`
		InstallHint struct {
			DocsURL string `json:"docs_url"`
			Command string `json:"command"`
		} `json:"install_hint"`
	}
	var body struct {
		Engines []engineJSON `json:"engines"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("解析 engines 回應失敗: %v", err)
	}

	var probe *engineJSON
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
		t.Error("shape-probe 不在任何來源 應為未安裝")
	}
	if probe.Source != "missing" {
		t.Errorf("shape-probe 來源應為 missing 實際 %s", probe.Source)
	}
	if probe.InstallHint.DocsURL == "" || probe.InstallHint.Command == "" {
		t.Errorf("shape-probe 應含安裝指引 實際 %+v", probe.InstallHint)
	}
}

func TestSetEngineDocker(t *testing.T) {
	srv, _ := newTestServer(t)
	t.Chdir(t.TempDir())             // .env 寫在 cwd 隔離到暫存目錄
	t.Setenv("COMPOSE_PROFILES", "") // 空環境變數 使讀取落到 .env

	post := func(name, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/engines/"+name+"/docker", strings.NewReader(body))
		srv.Handler().ServeHTTP(rec, req)
		return rec
	}

	/* 勾選 trivy docker */
	if rec := post("trivy", `{"enabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("勾選 trivy 回應碼 %d", rec.Code)
	}
	if !scanner.DockerProfileEnabled("trivy") {
		t.Error("trivy 應已勾選 docker profile")
	}

	/* 取消 trivy docker */
	if rec := post("trivy", `{"enabled":false}`); rec.Code != http.StatusOK {
		t.Fatalf("取消 trivy 回應碼 %d", rec.Code)
	}
	if scanner.DockerProfileEnabled("trivy") {
		t.Error("trivy 應已取消 docker profile")
	}

	/* 非 docker-capable 引擎應回 400 */
	if rec := post("gitleaks", `{"enabled":true}`); rec.Code != http.StatusBadRequest {
		t.Errorf("gitleaks 不支援 docker 應回 400 實際 %d", rec.Code)
	}
}

/* errStub 供假引擎模擬未安裝 */
var errStub = &stubError{}

type stubError struct{}

func (*stubError) Error() string { return "未安裝" }
