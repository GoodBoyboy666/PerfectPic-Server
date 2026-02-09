//go:build embed

package main

import (
	"embed"
	"io/fs"
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
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

func setupFrontend(r *gin.Engine, distFS fs.FS) []byte {
	assetsFS, err := fs.Sub(distFS, "assets")
	if err == nil {
		r.StaticFS("/assets", http.FS(assetsFS))
	} else {
		log.Printf("⚠️ 警告: 无法挂载 frontend/assets: %v", err)
	}

	indexData, err := fs.ReadFile(distFS, "index.html")
	if err != nil {
		log.Printf("⚠️ 警告: 无法读取 frontend/index.html: %v", err)
		return nil
	}

	return indexData
}
