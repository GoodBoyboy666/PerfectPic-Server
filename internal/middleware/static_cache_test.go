package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/service"

	"github.com/gin-gonic/gin"
)

// 测试内容：验证静态缓存中间件按配置写入 Cache-Control 头。
func TestStaticCacheMiddleware_SetsCacheControl(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	if err := db.DB.Save(&model.Setting{Key: consts.ConfigStaticCacheControl, Value: "public, max-age=60"}).Error; err != nil {
		t.Fatalf("设置配置项失败: %v", err)
	}
	service.ClearCache()

	r := gin.New()
	r.Use(StaticCacheMiddleware())
	r.GET("/x", func(c *gin.Context) { c.Status(http.StatusOK) })

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/x", nil))

	if got := w.Header().Get("Cache-Control"); got != "public, max-age=60" {
		t.Fatalf("Cache-Control = %q", got)
	}
}
