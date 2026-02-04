//go:build embed

package main

import (
	"embed"
	"io/fs"
)

//go:embed all:frontend
var embedFS embed.FS

// GetFrontendAssets 返回静态资源的文件系统
// 编译时带上 -tags embed 就会走这里
func GetFrontendAssets() fs.FS {
	// 获取 embedFS 下的 "frontend" 子目录作为根目录
	f, err := fs.Sub(embedFS, "frontend")
	if err != nil {
		panic(err)
	}
	return f
}
