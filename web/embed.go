// Package web 內嵌前端 SPA 靜態檔
//
// 前端 build 產出至 web/dist 後由此 embed 進 binary
// 實現單一 binary 同時是 CLI 與 Web 伺服器
package web

import "embed"

/* Dist 為前端 build 產出目錄

make build 前先跑 npm run build 產出 web/dist */
//
//go:embed dist/*
var Dist embed.FS
