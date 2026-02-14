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

// 测试内容：验证禁用验证码提供方时返回 disabled。
func TestGetCaptcha_DisabledProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: ""}).Error
	service.ClearCache()

	r := gin.New()
	r.GET("/captcha", GetCaptcha)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/captcha", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w.Code)
	}

	var resp struct {
		Provider string `json:"provider"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if resp.Provider != service.CaptchaProviderDisabled {
		t.Fatalf("期望 disabled provider，实际为 %q", resp.Provider)
	}
}

// 测试内容：验证不同提供方返回包含公共配置的响应。
func TestGetCaptcha_ProvidersWithPublicConfig(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	r := gin.New()
	r.GET("/captcha", GetCaptcha)

	cases := []struct {
		provider string
		key      string
	}{
		{provider: "turnstile", key: consts.ConfigCaptchaTurnstileSiteKey},
		{provider: "recaptcha", key: consts.ConfigCaptchaRecaptchaSiteKey},
		{provider: "hcaptcha", key: consts.ConfigCaptchaHcaptchaSiteKey},
		{provider: "geetest", key: consts.ConfigCaptchaGeetestCaptchaID},
	}

	for _, tc := range cases {
		_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: tc.provider}).Error
		_ = db.DB.Save(&model.Setting{Key: tc.key, Value: "pub"}).Error
		service.ClearCache()

		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/captcha", nil))
		if w.Code != http.StatusOK {
			t.Fatalf("provider %s 期望 200，实际为 %d body=%s", tc.provider, w.Code, w.Body.String())
		}
	}
}

// 测试内容：验证图片验证码提供方可返回验证码 ID 与图片。
func TestGetCaptchaImage_ImageProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "image"}).Error
	service.ClearCache()

	r := gin.New()
	r.GET("/captcha/image", GetCaptchaImage)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/captcha/image", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w.Code)
	}

	var resp struct {
		ID    string `json:"captcha_id"`
		Image string `json:"captcha_image"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if resp.ID == "" || resp.Image == "" {
		t.Fatalf("期望 captcha_id and captcha_image to be non-empty")
	}
}

// 测试内容：验证非图片提供方请求验证码图片时返回 400。
func TestGetCaptchaImage_NonImageProviderReturns400(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: ""}).Error
	service.ClearCache()

	r := gin.New()
	r.GET("/captcha/image", GetCaptchaImage)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/captcha/image", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d body=%s", w.Code, w.Body.String())
	}
}
