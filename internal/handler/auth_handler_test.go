package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/service"
	"perfect-pic-server/internal/utils"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// 测试内容：验证登录接口成功与错误密码时的返回码与 token 解析。
func TestLoginHandler_SuccessAndUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	// 测试中禁用验证码。
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: ""}).Error
	service.ClearCache()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "a@example.com", EmailVerified: true}
	_ = db.DB.Create(&u).Error

	r := gin.New()
	r.POST("/login", Login)

	body, _ := json.Marshal(gin.H{"username": "alice", "password": "abc12345"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d body=%s", w.Code, w.Body.String())
	}

	var okResp struct {
		Token string `json:"token"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &okResp)
	if okResp.Token == "" {
		t.Fatalf("期望得到 token")
	}
	if _, err := utils.ParseLoginToken(okResp.Token); err != nil {
		t.Fatalf("令牌解析失败: %v", err)
	}

	body2, _ := json.Marshal(gin.H{"username": "alice", "password": "wrongpass1"})
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader(body2)))
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际为 %d body=%s", w2.Code, w2.Body.String())
	}
}

// 测试内容：验证登录请求体解析失败时返回 400。
func TestLoginHandler_BindError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	r := gin.New()
	r.POST("/login", Login)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/login", bytes.NewReader([]byte("{bad"))))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证禁止注册时注册接口返回 403。
func TestRegisterHandler_ForbiddenWhenDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: ""}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigAllowRegister, Value: "false"}).Error
	service.ClearCache()

	r := gin.New()
	r.POST("/register", Register)

	body, _ := json.Marshal(gin.H{"username": "alice", "password": "abc12345", "email": "a@example.com"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
	if w.Code != http.StatusForbidden {
		t.Fatalf("期望 403，实际为 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证邮箱验证接口处理合法 token 并返回 200。
func TestEmailVerifyHandler_OK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "a@example.com", EmailVerified: false}
	_ = db.DB.Create(&u).Error

	token, err := utils.GenerateEmailToken(u.ID, u.Email, time.Hour)
	if err != nil {
		t.Fatalf("GenerateEmailToken: %v", err)
	}

	r := gin.New()
	r.POST("/auth/email-verify", EmailVerify)

	body, _ := json.Marshal(gin.H{"token": token})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth/email-verify", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("非预期的状态码 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证注册接口在允许注册时返回成功。
func TestRegisterHandler_Success(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: ""}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigAllowRegister, Value: "true"}).Error
	service.ClearCache()

	r := gin.New()
	r.POST("/register", Register)

	body, _ := json.Marshal(gin.H{"username": "alice_1", "password": "abc12345", "email": "a1@example.com"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证未知邮箱请求重置密码仍返回 200（避免泄露）。
func TestRequestPasswordResetHandler_Always200ForUnknownEmail(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: ""}).Error
	service.ClearCache()

	r := gin.New()
	r.POST("/auth/password/reset/request", RequestPasswordReset)

	body, _ := json.Marshal(gin.H{"email": "unknown@example.com"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth/password/reset/request", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证重置密码请求体解析失败时返回 400。
func TestRequestPasswordResetHandler_BindError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	r := gin.New()
	r.POST("/auth/password/reset/request", RequestPasswordReset)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth/password/reset/request", bytes.NewReader([]byte("{bad"))))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证重置密码接口在合法 token 时返回成功。
func TestResetPasswordHandler_OK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "a@example.com"}
	_ = db.DB.Create(&u).Error

	token, err := service.GenerateForgetPasswordToken(u.ID)
	if err != nil {
		t.Fatalf("GenerateForgetPasswordToken: %v", err)
	}

	r := gin.New()
	r.POST("/auth/password/reset", ResetPassword)

	body, _ := json.Marshal(gin.H{"token": token, "new_password": "abc123456"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth/password/reset", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证重置密码接口在非法 token 时返回 400。
func TestResetPasswordHandler_InvalidToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	r := gin.New()
	r.POST("/auth/password/reset", ResetPassword)

	body, _ := json.Marshal(gin.H{"token": "bad", "new_password": "abc123456"})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth/password/reset", bytes.NewReader(body)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证邮箱变更验证接口处理合法 token 并返回成功。
func TestEmailChangeVerifyHandler_OK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "old@example.com", EmailVerified: true}
	_ = db.DB.Create(&u).Error

	token, err := utils.GenerateEmailChangeToken(u.ID, "old@example.com", "new@example.com", time.Hour)
	if err != nil {
		t.Fatalf("GenerateEmailChangeToken: %v", err)
	}

	r := gin.New()
	r.POST("/auth/email-change-verify", EmailChangeVerify)

	body, _ := json.Marshal(gin.H{"token": token})
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth/email-change-verify", bytes.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证邮箱变更验证请求体解析失败时返回 400。
func TestEmailChangeVerifyHandler_BindError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	r := gin.New()
	r.POST("/auth/email-change-verify", EmailChangeVerify)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/auth/email-change-verify", bytes.NewReader([]byte("{bad"))))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d", w.Code)
	}
}

// 测试内容：验证获取注册状态接口返回 200。
func TestGetRegisterStateHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigAllowRegister, Value: "false"}).Error
	service.ClearCache()

	r := gin.New()
	r.GET("/register", GetRegisterState)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/register", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d body=%s", w.Code, w.Body.String())
	}
}
