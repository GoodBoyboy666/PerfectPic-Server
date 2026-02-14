package main

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"perfect-pic-server/internal/config"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/service"
	"perfect-pic-server/internal/testutils"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

// 测试内容：验证 splitTrustedProxyList 能正确拆分代理列表。
func TestSplitTrustedProxyList(t *testing.T) {
	got := splitTrustedProxyList(" 1.1.1.1,2.2.2.2; 3.3.3.3 \n4.4.4.4\t")
	if len(got) != 4 {
		t.Fatalf("期望 4 parts，实际为 %v", got)
	}
}

// 测试内容：验证未启用 embed 构建时前端资源与 index 数据为空。
func TestEmbedDisabledFrontendHooks(t *testing.T) {
	// 默认构建（不带 -tags embed）应使用 embed_disabled.go。
	if GetFrontendAssets() != nil {
		t.Fatalf("期望为 nil frontend assets in non-embed build")
	}
	r := gin.New()
	if data := setupFrontend(r, nil); data != nil {
		t.Fatalf("期望为 nil index data in non-embed build")
	}
}

// 测试内容：验证 exportAPI 会写出有效的 routes.json 路由列表。
func TestExportAPI_WritesRoutesJSON(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	r := gin.New()
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })
	exportAPI(r)

	b, err := os.ReadFile("routes.json")
	if err != nil {
		t.Fatalf("期望 routes.json: %v", err)
	}
	var routes []map[string]any
	if err := json.Unmarshal(b, &routes); err != nil {
		t.Fatalf("JSON 无效: %v", err)
	}
	if len(routes) == 0 {
		t.Fatalf("期望路由列表非空")
	}
}

// 测试内容：验证 NoRoute 处理在 API/上传/头像路径返回 404，根路径回退到 index，静态文件可被服务。
func TestGetNoRouteHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initTestConfig(t)

	dist := fstest.MapFS{
		"favicon.ico": &fstest.MapFile{Data: []byte("ico")},
	}
	indexData := []byte("<html>index</html>")

	r := gin.New()
	r.NoRoute(getNoRouteHandler(dist, indexData))

	// API 未找到
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/api/nope", nil))
	if w1.Code != http.StatusNotFound {
		t.Fatalf("期望 404，实际为 %d", w1.Code)
	}

	// 上传前缀未找到
	wu := httptest.NewRecorder()
	r.ServeHTTP(wu, httptest.NewRequest(http.MethodGet, "/imgs/nope.png", nil))
	if wu.Code != http.StatusNotFound {
		t.Fatalf("期望 404，实际为 %d", wu.Code)
	}

	// 头像前缀未找到
	wa := httptest.NewRecorder()
	r.ServeHTTP(wa, httptest.NewRequest(http.MethodGet, "/avatars/nope.png", nil))
	if wa.Code != http.StatusNotFound {
		t.Fatalf("期望 404，实际为 %d", wa.Code)
	}

	// 根路径回退到 index
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w2.Code)
	}

	// 已有根目录文件被服务
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
	if w3.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w3.Code)
	}
}

// 测试内容：确保创建上传与头像目录。
func TestEnsureDirectories_CreatesUploadAndAvatarDirs(t *testing.T) {
	initTestConfig(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	uploadPath, avatarPath := ensureDirectories()
	if _, err := os.Stat(uploadPath); err != nil {
		t.Fatalf("期望 upload dir exists: %v", err)
	}
	if _, err := os.Stat(avatarPath); err != nil {
		t.Fatalf("期望 avatar dir exists: %v", err)
	}
}

// 测试内容：验证 trusted_proxies 设置对信任代理的影响：空值禁用、有效列表生效、无效列表回退。
func TestApplyTrustedProxies_UsesSettingValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initTestConfig(t)
	setupTestDBForMain(t)

	// 空值会禁用信任。
	_ = db.DB.Save(&model.Setting{Key: "trusted_proxies", Value: ""}).Error
	service.ClearCache()
	r := gin.New()
	applyTrustedProxies(r)

	// 有效的代理列表。
	_ = db.DB.Save(&model.Setting{Key: "trusted_proxies", Value: "127.0.0.1,10.0.0.0/8"}).Error
	service.ClearCache()
	r2 := gin.New()
	applyTrustedProxies(r2)

	// 无效的代理列表应回退为 nil。
	_ = db.DB.Save(&model.Setting{Key: "trusted_proxies", Value: "not-a-cidr"}).Error
	service.ClearCache()
	r3 := gin.New()
	applyTrustedProxies(r3)
}

// 测试内容：验证 dist 为空时 NoRoute 对任意路径返回 404。
func TestGetNoRouteHandler_DistFSNil(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initTestConfig(t)

	r := gin.New()
	r.NoRoute(getNoRouteHandler(nil, nil))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/any", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("期望 404，实际为 %d", w.Code)
	}
}

// 测试内容：验证欢迎信息打印函数在测试配置下可执行。
func TestPrintWelcomeMessage(t *testing.T) {
	initTestConfig(t)
	printWelcomeMessage()
}

// 测试内容：验证静态文件挂载后上传与头像文件可被访问。
func TestSetupStaticFiles_ServesUploadsAndAvatars(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initTestConfig(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	uploadPath, avatarPath := ensureDirectories()
	_ = os.WriteFile(filepath.Join(uploadPath, "a.txt"), []byte("u"), 0644)
	_ = os.WriteFile(filepath.Join(avatarPath, "b.txt"), []byte("a"), 0644)

	r := gin.New()
	setupStaticFiles(r, uploadPath, avatarPath)

	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/imgs/a.txt", nil))
	if w1.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/avatars/b.txt", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w2.Code)
	}
}

func initTestConfig(t *testing.T) {
	t.Helper()

	cfgDir := t.TempDir()
	t.Setenv("PERFECT_PIC_SERVER_MODE", "debug")
	t.Setenv("PERFECT_PIC_JWT_SECRET", "test_secret")
	t.Setenv("PERFECT_PIC_JWT_EXPIRATION_HOURS", "24")
	t.Setenv("PERFECT_PIC_UPLOAD_PATH", "uploads/imgs")
	t.Setenv("PERFECT_PIC_UPLOAD_AVATAR_PATH", "uploads/avatars")
	t.Setenv("PERFECT_PIC_UPLOAD_URL_PREFIX", "/imgs/")
	t.Setenv("PERFECT_PIC_UPLOAD_AVATAR_URL_PREFIX", "/avatars/")
	t.Setenv("PERFECT_PIC_REDIS_ENABLED", "false")
	config.InitConfig(cfgDir)
}

func setupTestDBForMain(t *testing.T) *gorm.DB {
	gdb := testutils.SetupDB(t)
	service.ClearCache()
	return gdb
}

var _ fs.FS = fstest.MapFS{}
