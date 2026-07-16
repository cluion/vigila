# Vigila Makefile
# 常用開發指令統一入口

BINARY   := vigila
CMD_DIR  := ./cmd/vigila
PKG      := github.com/cluion/vigila

# 版本資訊 由 git 注入 本機 build 用 dev 預設值
VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0-dev")
COMMIT   := $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE     := $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS  := -X $(PKG)/internal/cli.version=$(VERSION) \
            -X $(PKG)/internal/cli.commit=$(COMMIT) \
            -X $(PKG)/internal/cli.date=$(DATE) \
            -X $(PKG)/internal/cli.builtBy=make

# sqlc 位置 GOPATH/bin
SQLC := $(shell go env GOPATH)/bin/sqlc

.PHONY: all build run test vet fmt tidy sqlc clean help

## all: 編譯 binary 預設目標
all: build

## build: 編譯前端並嵌入 Go binary
build: web-build
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(CMD_DIR)

## web-build: 編譯前端 SPA 到 web/dist
web-build:
	@if [ -d web/node_modules ]; then \
		cd web && npm run build; \
	else \
		echo "web/node_modules 不存在 跳過前端 build 使用既有 dist"; \
	fi

## go-build: 僅編譯 Go binary 不含前端
go-build:
	go build -ldflags "$(LDFLAGS)" -o bin/$(BINARY) $(CMD_DIR)

## run: 編譯後立即執行 範例 make run ARGS="version"
run: build
	./bin/$(BINARY) $(ARGS)

## test: 執行所有測試
test:
	go test ./... -v

## vet: 靜態檢查
vet:
	go vet ./...

## fmt: 格式化程式碼
fmt:
	gofmt -s -w .

## tidy: 整理 go.mod
tidy:
	go mod tidy

## sqlc: 重新產生 DB 存取程式碼 需先安裝 sqlc
sqlc:
	@if ! command -v $(SQLC) >/dev/null 2>&1; then \
		echo "安裝 sqlc..."; \
		go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest; \
	fi
	$(SQLC) generate

## clean: 清除建置產物
clean:
	rm -rf bin/ web/dist/

## help: 顯示所有可用目標
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //' | sed 's/://' | awk -F'#' '{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'
