package service

import (
	"fmt"
	"os"
	"path/filepath"
	"perfect-pic-server/internal/config"
	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"sync"
	"time"

	"github.com/google/uuid"
)

type ForgetPasswordToken struct {
	UserID    uint
	Token     string
	ExpiresAt time.Time
}

var (
	// passwordResetStore 存储忘记密码 Token
	// Key: UserID (uint), Value: ForgetPasswordToken
	passwordResetStore sync.Map
)

// GenerateForgetPasswordToken 生成忘记密码 Token，有效期 15 分钟
func GenerateForgetPasswordToken(userID uint) string {
	token := uuid.New().String()
	resetToken := ForgetPasswordToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}
	// 存储（覆盖之前的）
	passwordResetStore.Store(userID, resetToken)
	return token
}

// VerifyForgetPasswordToken 验证忘记密码 Token
func VerifyForgetPasswordToken(token string) (uint, bool) {
	var foundUserID uint
	var valid bool

	// 遍历 Map 查找 Token
	passwordResetStore.Range(func(key, value interface{}) bool {
		resetToken, ok := value.(ForgetPasswordToken)
		if !ok {
			return true
		}

		if resetToken.Token == token {
			// 找到 Token，无论是否过期，都先停止遍历
			// 并且为了保证一次性使用（防止重放）以及清理过期数据，直接删除
			passwordResetStore.Delete(key)

			if time.Now().Before(resetToken.ExpiresAt) {
				foundUserID = resetToken.UserID
				valid = true
			}
			return false // 停止遍历
		}

		// 顺便清理其他已过期的 Token (惰性清理)
		if time.Now().After(resetToken.ExpiresAt) {
			passwordResetStore.Delete(key)
		}
		return true
	})

	if valid {
		return foundUserID, true
	}

	return 0, false
}

// GetUserStorageQuota 获取用户由于配置或默认设置计算出的实际存储配额
func GetUserStorageQuota(user *model.User) int64 {
	if user.StorageQuota != nil {
		return *user.StorageQuota
	}
	// 调用同包下的 GetInt64
	quota := GetInt64(consts.ConfigDefaultStorageQuota)
	if quota == 0 {
		return 1073741824 // 兜底 1GB
	}
	return quota
}

// DeleteUserFiles 删除指定用户的所有关联文件（头像、上传的照片）
// 此函数只负责删除物理文件，不处理数据库记录的清理
func DeleteUserFiles(userID uint) error {
	cfg := config.Get()

	// 1. 删除头像目录
	// 头像存储结构: data/avatars/{userID}/filename
	avatarRoot := cfg.Upload.AvatarPath
	if avatarRoot == "" {
		avatarRoot = "uploads/avatars"
	}
	userAvatarDir := filepath.Join(avatarRoot, fmt.Sprintf("%d", userID))

	// RemoveAll 删除路径及其包含的任何子项。如果路径不存在，RemoveAll 返回 nil（无错误）。
	if err := os.RemoveAll(userAvatarDir); err != nil {
		// 记录日志或打印错误，但不中断后续操作
		fmt.Printf("Warning: Failed to delete avatar directory for user %d: %v\n", userID, err)
	}

	// 2. 查找并删除用户上传的所有图片
	var images []model.Image
	// Unscoped() 确保即使是软删除的图片也能被查出来删除文件
	if err := db.DB.Unscoped().Where("user_id = ?", userID).Find(&images).Error; err != nil {
		return fmt.Errorf("failed to retrieve user images: %w", err)
	}

	uploadRoot := cfg.Upload.Path
	if uploadRoot == "" {
		uploadRoot = "uploads/imgs"
	}

	for _, img := range images {
		// 转换路径分隔符以适配当前系统 (DB中存储的是 web 格式 '/')
		localPath := filepath.FromSlash(img.Path)
		fullPath := filepath.Join(uploadRoot, localPath)

		if err := os.Remove(fullPath); err != nil {
			if !os.IsNotExist(err) {
				fmt.Printf("Warning: Failed to delete image file %s: %v\n", fullPath, err)
			}
		}
	}

	return nil
}
