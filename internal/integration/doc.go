// Package integration 收錄端到端整合測試（build tag: integration）。
//
// 這些測試需要真實引擎 binary 或 docker，故以 build tag 隔離，不進一般 go test。
// 執行方式：go test -tags integration ./internal/integration/...
// 本檔不帶 build tag，確保套件在未帶 tag 時仍為合法（否則 go test ./... 會編譯失敗）。
package integration
