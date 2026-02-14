package service

import (
	"fmt"
	"perfect-pic-server/internal/config"
	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/utils"
	"time"

	"golang.org/x/crypto/bcrypt"
)

type UserProfile struct {
	ID           uint   `json:"id"`
	Username     string `json:"username"`
	Email        string `json:"email"`
	Avatar       string `json:"avatar"`
	Admin        bool   `json:"admin"`
	StorageQuota *int64 `json:"storage_quota"`
	StorageUsed  int64  `json:"storage_used"`
}

// GetUserProfile 获取用户个人资料。
func GetUserProfile(userID uint) (*UserProfile, error) {
	var user model.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		return nil, err
	}

	return &UserProfile{
		ID:           user.ID,
		Username:     user.Username,
		Email:        user.Email,
		Avatar:       user.Avatar,
		Admin:        user.Admin,
		StorageQuota: user.StorageQuota,
		StorageUsed:  user.StorageUsed,
	}, nil
}

// UpdateUsernameAndGenerateToken 更新用户名并签发新登录令牌。
func UpdateUsernameAndGenerateToken(userID uint, newUsername string, isAdmin bool) (string, string, error) {
	if ok, msg := utils.ValidateUsername(newUsername); !ok {
		return "", msg, nil
	}

	excludeID := userID
	usernameTaken, err := IsUsernameTaken(newUsername, &excludeID, true)
	if err != nil {
		return "", "", err
	}
	if usernameTaken {
		return "", "用户名已存在", nil
	}

	if err := db.DB.Model(&model.User{}).Where("id = ?", userID).Update("username", newUsername).Error; err != nil {
		return "", "", err
	}

	cfg := config.Get()
	token, err := utils.GenerateLoginToken(userID, newUsername, isAdmin, time.Hour*time.Duration(cfg.JWT.ExpirationHours))
	if err != nil {
		return "", "", err
	}

	return token, "", nil
}

// UpdatePasswordByOldPassword 使用旧密码校验后更新新密码。
func UpdatePasswordByOldPassword(userID uint, oldPassword, newPassword string) (string, error) {
	if ok, msg := utils.ValidatePassword(newPassword); !ok {
		return msg, nil
	}

	var user model.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		return "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(oldPassword)); err != nil {
		return "旧密码错误", nil
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}

	if err := db.DB.Model(&user).Update("password", string(hashedPassword)).Error; err != nil {
		return "", err
	}

	return "", nil
}

// RequestEmailChange 发起邮箱修改流程并异步发送验证邮件。
func RequestEmailChange(userID uint, password, newEmail string) (string, error) {
	if ok, msg := utils.ValidateEmail(newEmail); !ok {
		return msg, nil
	}

	var user model.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		return "", err
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return "密码错误", nil
	}

	if user.Email == newEmail {
		return "新邮箱不能与当前邮箱相同", nil
	}

	emailTaken, err := IsEmailTaken(newEmail, nil, true)
	if err != nil {
		return "", err
	}
	if emailTaken {
		return "该邮箱已被使用", nil
	}

	token, err := utils.GenerateEmailChangeToken(user.ID, user.Email, newEmail, 30*time.Minute)
	if err != nil {
		return "", err
	}

	baseURL := GetString(consts.ConfigBaseURL)
	if baseURL == "" {
		baseURL = "http://localhost"
	}
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}
	verifyURL := fmt.Sprintf("%s/auth/email-change-verify?token=%s", baseURL, token)

	if shouldSendEmail() {
		go func() {
			_ = SendEmailChangeVerification(newEmail, user.Username, user.Email, newEmail, verifyURL)
		}()
	}

	return "", nil
}
