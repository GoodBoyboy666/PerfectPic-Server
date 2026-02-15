package service

import (
	"testing"
	"time"

	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/utils"

	"golang.org/x/crypto/bcrypt"
)

// 测试内容：验证登录成功时返回有效 token 并解析出正确 claims。
func TestLoginUser_Success(t *testing.T) {
	setupTestDB(t)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{
		Username:      "alice",
		Password:      string(hashed),
		Admin:         true,
		Status:        1,
		Email:         "alice@example.com",
		EmailVerified: true,
	}
	if err := db.DB.Create(&u).Error; err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}

	token, err := LoginUser("alice", "abc12345")
	if err != nil {
		t.Fatalf("LoginUser 错误: %v", err)
	}
	claims, err := utils.ParseLoginToken(token)
	if err != nil {
		t.Fatalf("ParseLoginToken 错误: %v", err)
	}
	if claims.ID != u.ID || claims.Username != "alice" || !claims.Admin {
		t.Fatalf("非预期 claims: %+v", claims)
	}
}

// 测试内容：验证密码错误时返回未授权错误。
func TestLoginUser_WrongPasswordUnauthorized(t *testing.T) {
	setupTestDB(t)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{
		Username: "alice",
		Password: string(hashed),
		Status:   1,
	}
	_ = db.DB.Create(&u).Error

	_, err := LoginUser("alice", "wrongpass1")
	if err == nil {
		t.Fatalf("期望返回错误")
	}
	authErr, ok := AsAuthError(err)
	if !ok || authErr.Code != AuthErrorUnauthorized {
		t.Fatalf("期望 unauthorized auth 错误, got: %#v (%v)", authErr, err)
	}
}

// 测试内容：验证启用未验证拦截时未验证用户被禁止登录。
func TestLoginUser_BlockedUnverifiedForbidden(t *testing.T) {
	setupTestDB(t)

	// 启用未验证用户拦截。
	if err := db.DB.Save(&model.Setting{Key: consts.ConfigBlockUnverifiedUsers, Value: "true"}).Error; err != nil {
		t.Fatalf("设置配置项失败: %v", err)
	}
	ClearCache()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{
		Username:      "alice",
		Password:      string(hashed),
		Status:        1,
		Email:         "alice@example.com",
		EmailVerified: false,
	}
	if err := db.DB.Create(&u).Error; err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}

	_, err := LoginUser("alice", "abc12345")
	if err == nil {
		t.Fatalf("期望返回错误")
	}
	authErr, ok := AsAuthError(err)
	if !ok || authErr.Code != AuthErrorForbidden {
		t.Fatalf("期望 forbidden auth 错误, got: %#v (%v)", authErr, err)
	}
}

// 测试内容：验证注册参数不合法时返回校验错误。
func TestRegisterUser_ValidationError(t *testing.T) {
	setupTestDB(t)
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigAllowInit, Value: "false"}).Error
	ClearCache()

	err := RegisterUser("ab", "short", "bad-email")
	if err == nil {
		t.Fatalf("期望返回错误")
	}
	authErr, ok := AsAuthError(err)
	if !ok || authErr.Code != AuthErrorValidation {
		t.Fatalf("期望 validation auth 错误, got: %#v (%v)", authErr, err)
	}
}

// 测试内容：验证用户名重复时返回冲突错误。
func TestRegisterUser_DuplicateUsernameConflict(t *testing.T) {
	setupTestDB(t)
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigAllowInit, Value: "false"}).Error
	ClearCache()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "a1@example.com"}
	if err := db.DB.Create(&u).Error; err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}

	err := RegisterUser("alice", "abc12345", "alice2@example.com")
	if err == nil {
		t.Fatalf("期望返回错误")
	}
	authErr, ok := AsAuthError(err)
	if !ok || authErr.Code != AuthErrorConflict {
		t.Fatalf("期望 conflict auth 错误, got: %#v (%v)", authErr, err)
	}
}

// 测试内容：验证邮箱验证会设置验证状态并处理重复验证。
func TestVerifyEmail_SetsVerified(t *testing.T) {
	setupTestDB(t)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "alice@example.com", EmailVerified: false}
	if err := db.DB.Create(&u).Error; err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}

	token, err := utils.GenerateEmailToken(u.ID, u.Email, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateEmailToken: %v", err)
	}

	already, err := VerifyEmail(token)
	if err != nil {
		t.Fatalf("VerifyEmail 错误: %v", err)
	}
	if already {
		t.Fatalf("期望 alreadyVerified=false on first verify")
	}

	var got model.User
	if err := db.DB.First(&got, u.ID).Error; err != nil {
		t.Fatalf("加载用户失败: %v", err)
	}
	if !got.EmailVerified {
		t.Fatalf("期望 user to be verified")
	}

	already2, err := VerifyEmail(token)
	if err != nil {
		t.Fatalf("VerifyEmail second call 错误: %v", err)
	}
	if !already2 {
		t.Fatalf("期望 alreadyVerified=true on second verify")
	}
}

// 测试内容：验证注册成功会创建用户并正确初始化字段。
func TestRegisterUser_SuccessCreatesUser(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigAllowInit, Value: "false"}).Error
	ClearCache()

	if err := RegisterUser("alice_1", "abc12345", "a1@example.com"); err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}

	var u model.User
	if err := db.DB.Where("username = ?", "alice_1").First(&u).Error; err != nil {
		t.Fatalf("期望 user created: %v", err)
	}
	if u.EmailVerified {
		t.Fatalf("期望 email_verified false by default")
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte("abc12345")) != nil {
		t.Fatalf("期望 stored password to be bcrypt hash")
	}
}

// 测试内容：验证系统未初始化时注册被禁止（返回 forbidden）。
func TestRegisterUser_ForbiddenWhenSystemNotInitialized(t *testing.T) {
	setupTestDB(t)

	// 默认 allow_init=true；这里不写配置，确保走“未初始化”分支。
	err := RegisterUser("alice_1", "abc12345", "a1@example.com")
	if err == nil {
		t.Fatalf("期望返回错误")
	}
	authErr, ok := AsAuthError(err)
	if !ok || authErr.Code != AuthErrorForbidden {
		t.Fatalf("期望 forbidden auth 错误, got: %#v (%v)", authErr, err)
	}
}

// 测试内容：验证 AuthError.Error 返回消息文本。
func TestAuthError_ErrorString(t *testing.T) {
	e := &AuthError{Code: AuthErrorUnauthorized, Message: "x"}
	if e.Error() != "x" {
		t.Fatalf("期望返回错误 string: %q", e.Error())
	}
}

// 测试内容：验证邮箱变更令牌校验后会更新邮箱并保持已验证状态。
func TestVerifyEmailChange_UpdatesEmail(t *testing.T) {
	setupTestDB(t)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "a@example.com", EmailVerified: true}
	_ = db.DB.Create(&u).Error

	token, err := GenerateEmailChangeToken(u.ID, "a@example.com", "new@example.com")
	if err != nil {
		t.Fatalf("GenerateEmailChangeToken: %v", err)
	}

	if err := VerifyEmailChange(token); err != nil {
		t.Fatalf("VerifyEmailChange: %v", err)
	}

	var got model.User
	_ = db.DB.First(&got, u.ID).Error
	if got.Email != "new@example.com" || !got.EmailVerified {
		t.Fatalf("非预期 user email after change: %+v", got)
	}
}

// 测试内容：验证重置密码流程包含密码校验、一次性令牌与状态更新。
func TestResetPassword_Flow(t *testing.T) {
	setupTestDB(t)
	resetPasswordResetStore()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "a@example.com", EmailVerified: false}
	_ = db.DB.Create(&u).Error

	token, err := GenerateForgetPasswordToken(u.ID)
	if err != nil {
		t.Fatalf("GenerateForgetPasswordToken: %v", err)
	}

	// 无效的新密码
	err = ResetPassword(token, "short")
	if err == nil {
		t.Fatalf("期望返回错误 for 无效 new password")
	}

	// 由于一次性令牌会被删除，需要重新生成
	token, _ = GenerateForgetPasswordToken(u.ID)
	if err := ResetPassword(token, "abc123456"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	var got model.User
	_ = db.DB.First(&got, u.ID).Error
	if bcrypt.CompareHashAndPassword([]byte(got.Password), []byte("abc123456")) != nil {
		t.Fatalf("期望 password updated")
	}
	if !got.EmailVerified {
		t.Fatalf("期望 email_verified set true on reset")
	}
}

// 测试内容：验证请求重置密码对未知邮箱无泄露、对禁用用户返回禁止。
func TestRequestPasswordReset_Behavior(t *testing.T) {
	setupTestDB(t)
	resetPasswordResetStore()

	// 未知邮箱应返回 nil（避免用户枚举）。
	if err := RequestPasswordReset("unknown@example.com"); err != nil {
		t.Fatalf("期望为 nil for unknown email，实际为 %v", err)
	}

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "a@example.com", EmailVerified: true}
	_ = db.DB.Create(&u).Error

	if err := RequestPasswordReset("a@example.com"); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	b := model.User{Username: "banned", Password: string(hashed), Status: 2, Email: "b@example.com"}
	_ = db.DB.Create(&b).Error
	err := RequestPasswordReset("b@example.com")
	if err == nil {
		t.Fatalf("期望 forbidden 错误")
	}
	if ae, ok := AsAuthError(err); !ok || ae.Code != AuthErrorForbidden {
		t.Fatalf("期望 forbidden AuthError，实际为 %v", err)
	}
}
