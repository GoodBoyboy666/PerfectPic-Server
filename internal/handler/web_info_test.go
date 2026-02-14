package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/service"

	"github.com/gin-gonic/gin"
)

// 测试内容：验证 Web 信息接口仅返回允许的设置项。
func TestGetWebInfo_ReturnsAllowedKeys(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigSiteName, Value: "MySite"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigSiteDescription, Value: "Desc"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigSiteLogo, Value: "logo.png"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigSiteFavicon, Value: "favicon.ico"}).Error
	service.ClearCache()

	r := gin.New()
	r.GET("/webinfo", GetWebInfo)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/webinfo", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w.Code)
	}

	var items []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &items); err != nil {
		t.Fatalf("解析 JSON 失败: %v", err)
	}
	if len(items) != 4 {
		t.Fatalf("期望 4 items，实际为 %d", len(items))
	}
}

// 测试内容：验证图片前缀、头像前缀与默认配额接口返回成功。
func TestWebInfoPrefixHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	r := gin.New()
	r.GET("/image_prefix", GetImagePrefix)
	r.GET("/avatar_prefix", GetAvatarPrefix)
	r.GET("/default_storage_quota", GetDefaultStorageQuota)

	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/image_prefix", nil))
	if w1.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w1.Code)
	}

	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/avatar_prefix", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w2.Code)
	}

	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, httptest.NewRequest(http.MethodGet, "/default_storage_quota", nil))
	if w3.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w3.Code)
	}
}
