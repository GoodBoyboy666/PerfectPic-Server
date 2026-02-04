package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"perfect-pic-server/internal/config"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/middleware"
	"perfect-pic-server/internal/router"
	"perfect-pic-server/internal/service"
	"strings"
	"syscall"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	AppName     = "Perfect Pic Server"
	AppVersion  = "dev"
	BuildTime   = "unknown"
	GitCommit   = "unknown"
	FrontendVer = "unknown"
)

func main() {

	exportRoutes := flag.Bool("export", false, "导出路由到 routes.json 并退出")
	flag.Parse()

	config.InitConfig()
	db.InitDB()
	service.InitializeSettings()

	uploadPath := config.Get().Upload.Path
	checkSecurePath(uploadPath)
	if err := os.MkdirAll(uploadPath, 0755); err != nil {
		log.Fatal("无法创建上传目录: ", err)
	}

	avatarPath := config.Get().Upload.AvatarPath
	checkSecurePath(avatarPath)
	if err := os.MkdirAll(avatarPath, 0755); err != nil {
		log.Fatal("无法创建头像目录: ", err)
	}

	gin.SetMode(config.Get().Server.Mode)

	r := gin.Default()
	router.InitRouter(r)

	// 使用带缓存控制的静态文件服务
	r.Group(config.Get().Upload.URLPrefix, middleware.StaticCacheMiddleware()).
		StaticFS("", gin.Dir(uploadPath, false))

	r.Group(config.Get().Upload.AvatarURLPrefix, middleware.StaticCacheMiddleware()).
		StaticFS("", gin.Dir(avatarPath, false))

	distFS := GetFrontendAssets()
	var indexData []byte

	if distFS != nil {
		assetsFS, _ := fs.Sub(distFS, "assets")
		r.StaticFS("/assets", http.FS(assetsFS))

		// 预读取 index.html
		var err error
		indexData, err = fs.ReadFile(distFS, "index.html")
		if err != nil {
			log.Printf("⚠️ 警告: 无法读取 frontend/index.html: %v", err)
		}
	}

	r.NoRoute(func(c *gin.Context) {
		if strings.HasPrefix(c.Request.URL.Path, "/api") {
			c.JSON(404, gin.H{"error": "API not found"})
			return
		}
		if strings.HasPrefix(c.Request.URL.Path, config.Get().Upload.URLPrefix) {
			c.JSON(404, gin.H{"error": "Upload not found"})
			return
		}

		if distFS == nil {
			c.JSON(404, gin.H{"error": "Page not found"})
			return
		}

		// 尝试直接服务根目录下的静态文件 (如 favicon.ico, manifest.json)
		path := strings.TrimPrefix(c.Request.URL.Path, "/")

		// 如果 path 为空（即访问根路径 /），直接返回 index.html
		if path == "" {
			c.Data(200, "text/html; charset=utf-8", indexData)
			return
		}

		f, err := distFS.Open(path)
		if err == nil {
			defer f.Close()
			stat, _ := f.Stat()
			if !stat.IsDir() {
				c.FileFromFS(path, http.FS(distFS))
				return
			}
		}

		// SPA 回退：服务 index.html 内容
		c.Data(200, "text/html; charset=utf-8", indexData)
	})

	// 导出模式
	if *exportRoutes {
		exportAPI(r)
		return // 导出后直接退出程序，不启动 Web 服务
	}

	// 打印启动欢迎语
	printWelcomeMessage(distFS)

	// 停机配置
	srv := &http.Server{
		Addr:    ":" + config.Get().Server.Port,
		Handler: r,
	}

	go func() {
		// 服务连接
		log.Printf("🚀 服务启动成功，运行在 :%s\n", config.Get().Server.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("❌ 服务启动失败: %s\n", err)
		}
	}()

	// 等待中断信号关闭服务器（设置 5 秒的超时时间）
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("🛑 正在关闭服务...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatal("❌ 服务强制关闭:", err)
	}
	log.Println("✅ 服务已退出")
}

func printWelcomeMessage(distFS fs.FS) {

	fmt.Println()
	fmt.Println(" ┌───────────────────────────────────────────────────────┐")
	fmt.Printf(" │   🚀  %s\n", AppName)
	fmt.Println(" ├───────────────────────────────────────────────────────┤")
	fmt.Printf(" │   📦  后端版本 : %s\n", AppVersion)
	fmt.Printf(" │   💻  前端构建 : %s\n", FrontendVer)
	fmt.Printf(" │   🔧  Git 提交 : %s\n", GitCommit)
	fmt.Printf(" │   🕒  构建时间 : %s\n", BuildTime)
	fmt.Printf(" │   🔥  服务端口 : %s\n", config.Get().Server.Port)
	fmt.Println(" └───────────────────────────────────────────────────────┘")
	fmt.Println()
}

func exportAPI(r *gin.Engine) {
	routes := r.Routes()

	// 简单的结构体，只留关键信息
	type RouteInfo struct {
		Method  string `json:"method"`
		Path    string `json:"path"`
		Handler string `json:"handler"`
	}

	var exportList []RouteInfo
	for _, route := range routes {
		exportList = append(exportList, RouteInfo{
			Method:  route.Method,
			Path:    route.Path,
			Handler: route.Handler,
		})
	}

	file, _ := json.MarshalIndent(exportList, "", "  ")
	_ = os.WriteFile("routes.json", file, 0644)

	println("✅ 路由已成功导出到 routes.json")
}

func checkSecurePath(path string) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		log.Fatalf("❌ 路径解析失败: %v", err)
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("❌ 无法获取当前工作目录: %v", err)
	}

	// 检查是否直接指向项目根目录
	if absPath == cwd {
		log.Fatalf("❌ 安全配置错误: 静态资源目录 '%s' 不能设置为项目根目录！这会导致源代码泄露。", path)
	}

	// 检查路径安全
	rel, err := filepath.Rel(cwd, absPath)
	if err == nil && !strings.HasPrefix(rel, "..") {
		// 统一路径分隔符为 / 方便匹配
		relSlash := filepath.ToSlash(rel)

		// 允许的安全目录列表
		// 只有位于这些目录下的路径才被允许作为静态资源目录
		allowedDirs := []string{
			"uploads",
			"public",
			"assets",
			"static",
			"tmp",
		}

		isAllowed := false
		firstComponent := strings.Split(relSlash, "/")[0]
		for _, allowed := range allowedDirs {
			if strings.EqualFold(firstComponent, allowed) {
				isAllowed = true
				break
			}
		}

		if !isAllowed {
			log.Fatalf("❌ 安全配置错误: 静态资源目录 '%s' (解析为: '%s') 必须位于项目根目录下的安全子目录中 (如 %v)。\n这能防止意外暴露源代码或配置文件 (如 internal, cmd 等)。", path, relSlash, allowedDirs)
		}
	}
}
