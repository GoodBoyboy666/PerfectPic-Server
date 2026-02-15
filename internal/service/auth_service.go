package service

import (
	"errors"
	"fmt"
	"perfect-pic-server/internal/config"
	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/utils"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AuthErrorCode string

const (
	AuthErrorValidation   AuthErrorCode = "validation"
	AuthErrorUnauthorized AuthErrorCode = "unauthorized"
	AuthErrorForbidden    AuthErrorCode = "forbidden"
	AuthErrorConflict     AuthErrorCode = "conflict"
	AuthErrorNotFound     AuthErrorCode = "not_found"
	AuthErrorInternal     AuthErrorCode = "internal"
)

type AuthError struct {
	Code    AuthErrorCode
	Message string
}

// Error 返回认证错误的消息文本。
func (e *AuthError) Error() string {
	return e.Message
}

// newAuthError 构造统一的认证错误对象。
func newAuthError(code AuthErrorCode, message string) error {
	return &AuthError{Code: code, Message: message}
}

// AsAuthError 将通用 error 安全转换为 AuthError。
func AsAuthError(err error) (*AuthError, bool) {
	var authErr *AuthError
	if errors.As(err, &authErr) {
		return authErr, true
	}
	return nil, false
}

// LoginUser 执行登录鉴权并返回登录令牌。
func LoginUser(username, password string) (string, error) {
	var user model.User
	result := db.DB.Where("username = ?", username).First(&user)
	if result.Error != nil {
		return "", newAuthError(AuthErrorUnauthorized, "用户名或密码错误")
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "", newAuthError(AuthErrorUnauthorized, "用户名或密码错误")
	}

	if user.Status == 2 {
		return "", newAuthError(AuthErrorForbidden, "该账号已被封禁")
	}
	if user.Status == 3 {
		return "", newAuthError(AuthErrorForbidden, "该账号已停用")
	}

	if GetBool(consts.ConfigBlockUnverifiedUsers) {
		if user.Email != "" && !user.EmailVerified {
			return "", newAuthError(AuthErrorForbidden, "请先验证邮箱后再登录")
		}
	}

	cfg := config.Get()
	token, err := utils.GenerateLoginToken(user.ID, user.Username, user.Admin, time.Hour*time.Duration(cfg.JWT.ExpirationHours))
	if err != nil {
		return "", newAuthError(AuthErrorInternal, "登录失败，请稍后重试")
	}

	return token, nil
}

// RegisterUser 执行用户注册并异步发送邮箱验证邮件。
//
//nolint:gocyclo
func RegisterUser(username, password, email string) error {
	// 系统未初始化时禁止注册：避免在还未创建管理员/完成基础配置时产生普通用户。
	if !IsSystemInitialized() {
		return newAuthError(AuthErrorForbidden, "系统尚未初始化，请先完成初始化")
	}

	if ok, msg := utils.ValidatePassword(password); !ok {
		return newAuthError(AuthErrorValidation, msg)
	}

	if ok, msg := utils.ValidateUsername(username); !ok {
		return newAuthError(AuthErrorValidation, msg)
	}

	if ok, msg := utils.ValidateEmail(email); !ok {
		return newAuthError(AuthErrorValidation, msg)
	}

	if !GetBool(consts.ConfigAllowRegister) {
		return newAuthError(AuthErrorForbidden, "注册功能已关闭")
	}

	usernameTaken, err := IsUsernameTaken(username, nil, true)
	if err != nil {
		return newAuthError(AuthErrorInternal, "注册失败，请稍后重试")
	}
	if usernameTaken {
		return newAuthError(AuthErrorConflict, "用户名已存在")
	}

	emailTaken, err := IsEmailTaken(email, nil, true)
	if err != nil {
		return newAuthError(AuthErrorInternal, "注册失败，请稍后重试")
	}
	if emailTaken {
		return newAuthError(AuthErrorConflict, "邮箱已被注册")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return newAuthError(AuthErrorInternal, "密码加密失败")
	}

	newUser := model.User{
		Username:      username,
		Password:      string(hashedPassword),
		Email:         email,
		EmailVerified: false,
		Admin:         false,
		Avatar:        "",
	}

	if err := db.DB.Create(&newUser).Error; err != nil {
		return newAuthError(AuthErrorInternal, "注册失败，请稍后重试")
	}

	verifyToken, err := utils.GenerateEmailToken(newUser.ID, newUser.Email, 30*time.Minute)
	if err != nil {
		return newAuthError(AuthErrorInternal, "注册失败，请稍后重试")
	}

	baseURL := GetString(consts.ConfigBaseURL)
	if baseURL == "" {
		baseURL = "http://localhost"
	}
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}

	verifyURL := fmt.Sprintf("%s/auth/email-verify?token=%s", baseURL, verifyToken)
	if shouldSendEmail() {
		go func() {
			_ = SendVerificationEmail(newUser.Email, newUser.Username, verifyURL)
		}()
	}

	return nil
}

// VerifyEmail 验证邮箱激活令牌。
// 返回值第一个参数为 true 表示该邮箱已是验证状态。
func VerifyEmail(token string) (bool, error) {
	claims, err := utils.ParseEmailToken(token)
	if err != nil {
		return false, newAuthError(AuthErrorValidation, "验证链接已失效或不正确")
	}

	if claims.Type != "email_verify" {
		return false, newAuthError(AuthErrorValidation, "无效的验证 Token 类型")
	}

	var user model.User
	if err := db.DB.First(&user, claims.ID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return false, newAuthError(AuthErrorNotFound, "用户不存在")
		}
		return false, newAuthError(AuthErrorInternal, "验证失败，请稍后重试")
	}

	if user.Email != claims.Email {
		return false, newAuthError(AuthErrorValidation, "邮箱不匹配，请重新发起验证")
	}

	if user.EmailVerified {
		return true, nil
	}

	user.EmailVerified = true
	if err := db.DB.Save(&user).Error; err != nil {
		return false, newAuthError(AuthErrorInternal, "验证失败，请稍后重试")
	}

	return false, nil
}

// VerifyEmailChange 验证邮箱变更令牌并更新邮箱。
func VerifyEmailChange(token string) error {
	payload, ok := VerifyEmailChangeToken(token)
	if !ok {
		return newAuthError(AuthErrorValidation, "验证链接已失效或不正确")
	}

	var user model.User
	if err := db.DB.First(&user, payload.UserID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return newAuthError(AuthErrorNotFound, "用户不存在")
		}
		return newAuthError(AuthErrorInternal, "邮箱修改失败，请稍后重试")
	}

	if user.Email != payload.OldEmail {
		return newAuthError(AuthErrorValidation, "您的当前邮箱已变更，该验证链接已失效")
	}

	excludeID := payload.UserID
	emailTaken, err := IsEmailTaken(payload.NewEmail, &excludeID, true)
	if err != nil {
		return newAuthError(AuthErrorInternal, "邮箱修改失败，请稍后重试")
	}
	if emailTaken {
		return newAuthError(AuthErrorConflict, "新邮箱已被其他用户占用，无法修改")
	}

	user.Email = payload.NewEmail
	user.EmailVerified = true
	if err := db.DB.Save(&user).Error; err != nil {
		return newAuthError(AuthErrorInternal, "邮箱修改失败，请稍后重试")
	}

	return nil
}

// RequestPasswordReset 发起忘记密码流程并异步发送重置邮件。
func RequestPasswordReset(email string) error {
	var user model.User
	if err := db.DB.Where("email = ?", email).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return newAuthError(AuthErrorInternal, "生成重置链接失败，请稍后重试")
	}

	if user.Status == 2 || user.Status == 3 {
		return newAuthError(AuthErrorForbidden, "该账号已被封禁或停用，无法重置密码")
	}

	token, err := GenerateForgetPasswordToken(user.ID)
	if err != nil {
		return newAuthError(AuthErrorInternal, "生成重置链接失败，请稍后重试")
	}

	baseURL := GetString(consts.ConfigBaseURL)
	if baseURL == "" {
		baseURL = "http://localhost"
	}
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}
	resetURL := fmt.Sprintf("%s/auth/reset-password?token=%s", baseURL, token)

	if shouldSendEmail() {
		go func() {
			_ = SendPasswordResetEmail(user.Email, user.Username, resetURL)
		}()
	}

	return nil
}

// ResetPassword 使用重置令牌设置新密码。
func ResetPassword(token, newPassword string) error {
	if ok, msg := utils.ValidatePassword(newPassword); !ok {
		return newAuthError(AuthErrorValidation, msg)
	}

	userID, valid := VerifyForgetPasswordToken(token)
	if !valid {
		return newAuthError(AuthErrorValidation, "重置链接无效或已过期")
	}

	var user model.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return newAuthError(AuthErrorNotFound, "用户不存在")
		}
		return newAuthError(AuthErrorInternal, "密码重置失败")
	}

	if user.Status == 2 || user.Status == 3 {
		return newAuthError(AuthErrorForbidden, "该账号已被封禁或停用")
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return newAuthError(AuthErrorInternal, "密码加密失败")
	}

	user.Password = string(hashedPassword)
	user.EmailVerified = true

	if err := db.DB.Save(&user).Error; err != nil {
		return newAuthError(AuthErrorInternal, "密码重置失败")
	}

	return nil
}
