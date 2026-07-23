package core

import "testing"

/* TestOrchestratorOptions 確認鏈式設定回傳同一實例且設值生效 */
func TestOrchestratorOptions(t *testing.T) {
	o := New(nil)

	called := false
	ret := o.
		WithSBOM(true).
		WithTriggerSource("web").
		WithEvent(func(string, interface{}) { called = true })

	if ret != o {
		t.Error("option 應回傳同一 Orchestrator 供鏈式呼叫")
	}
	if !o.sbom {
		t.Error("WithSBOM(true) 應設 sbom 為 true")
	}
	if o.triggerSource != "web" {
		t.Errorf("triggerSource = %q 預期 web", o.triggerSource)
	}
	if o.onEvent == nil {
		t.Fatal("WithEvent 應設定回呼")
	}
	o.onEvent("test", nil)
	if !called {
		t.Error("設定的事件回呼應可被呼叫")
	}
}
