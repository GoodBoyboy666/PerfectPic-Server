package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"perfect-pic-server/internal/config"
	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/utils"
	"strconv"
	"sync"
	"time"
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
func GenerateForgetPasswordToken(userID uint) (string, error) {
	// 使用 crypto/rand 生成 32 字节的高熵随机字符串 (64字符Hex)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	resetToken := ForgetPasswordToken{
		UserID:    userID,
		Token:     token,
		ExpiresAt: time.Now().Add(15 * time.Minute),
	}

	if redisClient := GetRedisClient(); redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		// 保证一个用户只有一个有效 token
		userKey := RedisKey("password_reset", "user", strconv.FormatUint(uint64(userID), 10))
		if oldToken, err := redisClient.Get(ctx, userKey).Result(); err == nil && oldToken != "" {
			oldTokenKey := RedisKey("password_reset", "token", oldToken)
			_ = redisClient.Del(ctx, oldTokenKey).Err()
		}

		tokenKey := RedisKey("password_reset", "token", token)
		if err := redisClient.Set(ctx, tokenKey, strconv.FormatUint(uint64(userID), 10), 15*time.Minute).Err(); err == nil {
			_ = redisClient.Set(ctx, userKey, token, 15*time.Minute).Err()
			return token, nil
		}
	}

	// 存储（覆盖之前的）
	passwordResetStore.Store(userID, resetToken)
	return token, nil
}

// VerifyForgetPasswordToken 验证忘记密码 Token
func VerifyForgetPasswordToken(token string) (uint, bool) {
	if redisClient := GetRedisClient(); redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		tokenKey := RedisKey("password_reset", "token", token)
		uidStr, err := redisClient.Get(ctx, tokenKey).Result()
		if err == nil {
			_ = redisClient.Del(ctx, tokenKey).Err()

			uid, parseErr := strconv.ParseUint(uidStr, 10, 64)
			if parseErr == nil {
				userKey := RedisKey("password_reset", "user", strconv.FormatUint(uid, 10))
				_ = redisClient.Del(ctx, userKey).Err()
				return uint(uid), true
			}
			return 0, false
		}
	}

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

// GetSystemDefaultStorageQuota 获取系统默认存储配额
func GetSystemDefaultStorageQuota() int64 {
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
	avatarRootAbs, err := filepath.Abs(avatarRoot)
	if err != nil {
		return fmt.Errorf("failed to resolve avatar root: %w", err)
	}
	// 先校验头像根目录节点本身，避免根目录直接是符号链接。
	if err := utils.EnsurePathNotSymlink(avatarRootAbs); err != nil {
		return fmt.Errorf("avatar root symlink risk: %w", err)
	}

	userAvatarDir, err := utils.SecureJoin(avatarRootAbs, fmt.Sprintf("%d", userID))
	if err != nil {
		return fmt.Errorf("failed to build avatar dir: %w", err)
	}
	// 在执行 RemoveAll 前再做一次链路检查，确保目标目录链路未被并发替换为符号链接。
	if err := utils.EnsureNoSymlinkBetween(avatarRootAbs, userAvatarDir); err != nil {
		return fmt.Errorf("avatar dir symlink risk: %w", err)
	}

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
	uploadRootAbs, err := filepath.Abs(uploadRoot)
	if err != nil {
		return fmt.Errorf("failed to resolve upload root: %w", err)
	}
	// 先校验上传根目录节点本身，避免根目录直接是符号链接。
	if err := utils.EnsurePathNotSymlink(uploadRootAbs); err != nil {
		return fmt.Errorf("upload root symlink risk: %w", err)
	}

	for _, img := range images {
		// 转换路径分隔符以适配当前系统 (DB中存储的是 web 格式 '/')
		localPath := filepath.FromSlash(img.Path)
		fullPath, secureErr := utils.SecureJoin(uploadRootAbs, localPath)
		if secureErr != nil {
			fmt.Printf("Warning: Skip unsafe image path for user %d (%s): %v\n", userID, img.Path, secureErr)
			continue
		}

		if err := os.Remove(fullPath); err != nil {
			if !os.IsNotExist(err) {
				fmt.Printf("Warning: Failed to delete image file %s: %v\n", fullPath, err)
			}
		}
	}

	return nil
}
