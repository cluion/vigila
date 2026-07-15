// Package main 為 Vigila 程式進入點
package main

import (
	/* 匿名 import 觸發各 adapter 的 init 註冊 */
	_ "github.com/cluion/vigila/internal/scanner/semgrep"

	"github.com/cluion/vigila/internal/cli"
)

func main() {
	cli.Execute()
}
