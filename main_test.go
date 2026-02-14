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

func TestSplitTrustedProxyList(t *testing.T) {
	got := splitTrustedProxyList(" 1.1.1.1,2.2.2.2; 3.3.3.3 \n4.4.4.4\t")
	if len(got) != 4 {
		t.Fatalf("expected 4 parts, got %v", got)
	}
}

func TestEmbedDisabledFrontendHooks(t *testing.T) {
	// Default build (no -tags embed) should use embed_disabled.go.
	if GetFrontendAssets() != nil {
		t.Fatalf("expected nil frontend assets in non-embed build")
	}
	r := gin.New()
	if data := setupFrontend(r, nil); data != nil {
		t.Fatalf("expected nil index data in non-embed build")
	}
}

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
		t.Fatalf("expected routes.json: %v", err)
	}
	var routes []map[string]any
	if err := json.Unmarshal(b, &routes); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if len(routes) == 0 {
		t.Fatalf("expected non-empty routes")
	}
}

func TestGetNoRouteHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initTestConfig(t)

	dist := fstest.MapFS{
		"favicon.ico": &fstest.MapFile{Data: []byte("ico")},
	}
	indexData := []byte("<html>index</html>")

	r := gin.New()
	r.NoRoute(getNoRouteHandler(dist, indexData))

	// API not found
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/api/nope", nil))
	if w1.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w1.Code)
	}

	// Upload prefix not found
	wu := httptest.NewRecorder()
	r.ServeHTTP(wu, httptest.NewRequest(http.MethodGet, "/imgs/nope.png", nil))
	if wu.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", wu.Code)
	}

	// Avatar prefix not found
	wa := httptest.NewRecorder()
	r.ServeHTTP(wa, httptest.NewRequest(http.MethodGet, "/avatars/nope.png", nil))
	if wa.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", wa.Code)
	}

	// Root falls back to index
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Code)
	}

	// Existing root file served
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, httptest.NewRequest(http.MethodGet, "/favicon.ico", nil))
	if w3.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w3.Code)
	}
}

func TestEnsureDirectories_CreatesUploadAndAvatarDirs(t *testing.T) {
	initTestConfig(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	uploadPath, avatarPath := ensureDirectories()
	if _, err := os.Stat(uploadPath); err != nil {
		t.Fatalf("expected upload dir exists: %v", err)
	}
	if _, err := os.Stat(avatarPath); err != nil {
		t.Fatalf("expected avatar dir exists: %v", err)
	}
}

func TestApplyTrustedProxies_UsesSettingValue(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initTestConfig(t)
	setupTestDBForMain(t)

	// Empty disables trust.
	_ = db.DB.Save(&model.Setting{Key: "trusted_proxies", Value: ""}).Error
	service.ClearCache()
	r := gin.New()
	applyTrustedProxies(r)

	// Valid proxies list.
	_ = db.DB.Save(&model.Setting{Key: "trusted_proxies", Value: "127.0.0.1,10.0.0.0/8"}).Error
	service.ClearCache()
	r2 := gin.New()
	applyTrustedProxies(r2)

	// Invalid proxies list should fall back to nil.
	_ = db.DB.Save(&model.Setting{Key: "trusted_proxies", Value: "not-a-cidr"}).Error
	service.ClearCache()
	r3 := gin.New()
	applyTrustedProxies(r3)
}

func TestGetNoRouteHandler_DistFSNil(t *testing.T) {
	gin.SetMode(gin.TestMode)
	initTestConfig(t)

	r := gin.New()
	r.NoRoute(getNoRouteHandler(nil, nil))

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/any", nil))
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
}

func TestPrintWelcomeMessage(t *testing.T) {
	initTestConfig(t)
	printWelcomeMessage()
}

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
		t.Fatalf("expected 200, got %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/avatars/b.txt", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w2.Code)
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
