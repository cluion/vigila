// Package main 為 Vigila 程式進入點
package main

import (
	/* 匿名 import 觸發各 adapter 的 init 註冊 */
	_ "github.com/cluion/vigila/internal/scanner/gitleaks"
	_ "github.com/cluion/vigila/internal/scanner/semgrep"
	_ "github.com/cluion/vigila/internal/scanner/trivy"

	"github.com/cluion/vigila/internal/cli"
)

func main() {
	cli.Execute()
}
