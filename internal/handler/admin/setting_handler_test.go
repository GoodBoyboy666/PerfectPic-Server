package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/service"

	"github.com/gin-gonic/gin"
)

// 测试内容：验证管理员获取与更新设置接口的基本流程。
func TestGetAndUpdateSettingsHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	_ = db.DB.Create(&model.Setting{Key: "k1", Value: "v1"}).Error
	service.ClearCache()

	r := gin.New()
	r.GET("/settings", GetSettings)
	r.PATCH("/settings", UpdateSettings)

	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/settings", nil))
	if w1.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d body=%s", w1.Code, w1.Body.String())
	}

	body, _ := json.Marshal([]UpdateSettingRequest{{Key: "k1", Value: "v2"}, {Key: "k2", Value: "v3"}})
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodPatch, "/settings", bytes.NewReader(body)))
	if w2.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d body=%s", w2.Code, w2.Body.String())
	}

	var s model.Setting
	_ = db.DB.Where("key = ?", "k1").First(&s).Error
	if s.Value != "v2" {
		t.Fatalf("期望 updated k1=v2，实际为 %q", s.Value)
	}
}

// 测试内容：验证发送测试邮件接口对无效邮箱返回 400。
func TestSendTestEmailHandler_InvalidEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	r := gin.New()
	r.POST("/email/test", SendTestEmail)

	body, _ := json.Marshal(gin.H{"to_email": "bad-email"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/email/test", bytes.NewReader(body)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证 SMTP 主机缺失时发送测试邮件返回 500。
func TestSendTestEmailHandler_SMTPMissingHostReturns500(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	r := gin.New()
	r.POST("/email/test", SendTestEmail)

	body, _ := json.Marshal(gin.H{"to_email": "a@example.com"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/email/test", bytes.NewReader(body)))
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("期望 500，实际为 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证更新设置接口在请求体绑定失败时返回 400。
func TestUpdateSettingsHandler_BindError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	r := gin.New()
	r.PATCH("/settings", UpdateSettings)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPatch, "/settings", bytes.NewReader([]byte("{bad"))))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d body=%s", w.Code, w.Body.String())
	}
}
