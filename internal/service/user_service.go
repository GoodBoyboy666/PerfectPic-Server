package service

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
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

	"github.com/redis/go-redis/v9"
)

type ForgetPasswordToken struct {
	UserID    uint
	Token     string
	ExpiresAt time.Time
}

type EmailChangeToken struct {
	UserID    uint
	Token     string
	OldEmail  string
	NewEmail  string
	ExpiresAt time.Time
}

type emailChangeRedisPayload struct {
	UserID   uint   `json:"user_id"`
	OldEmail string `json:"old_email"`
	NewEmail string `json:"new_email"`
}

var (
	// passwordResetStore 存储忘记密码 Token
	// Key: UserID (uint), Value: ForgetPasswordToken
	passwordResetStore sync.Map

	// emailChangeStore 存储修改邮箱 Token
	// Key: UserID (uint), Value: EmailChangeToken
	emailChangeStore sync.Map
)

var errRedisTokenCASMismatch = errors.New("redis token cas mismatch")

func verifyAndConsumeRedisTokenPair(
	ctx context.Context,
	redisClient *redis.Client,
	tokenKey string,
	userKey string,
	expectedUserToken string,
	expectedTokenValue string,
) error {
	var consumed bool
	watchErr := redisClient.Watch(ctx, func(tx *redis.Tx) error {
		currentUserToken, getErr := tx.Get(ctx, userKey).Result()
		if getErr != nil {
			if errors.Is(getErr, redis.Nil) {
				return redis.TxFailedErr
			}
			return getErr
		}
		if currentUserToken != expectedUserToken {
			return redis.TxFailedErr
		}

		currentTokenValue, tokenErr := tx.Get(ctx, tokenKey).Result()
		if tokenErr != nil {
			if errors.Is(tokenErr, redis.Nil) {
				return redis.TxFailedErr
			}
			return tokenErr
		}
		if currentTokenValue != expectedTokenValue {
			return redis.TxFailedErr
		}

		_, pipeErr := tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Del(ctx, tokenKey)
			pipe.Del(ctx, userKey)
			return nil
		})
		if pipeErr != nil {
			return pipeErr
		}

		consumed = true
		return nil
	}, userKey, tokenKey)

	if watchErr == nil && consumed {
		return nil
	}
	if errors.Is(watchErr, redis.TxFailedErr) || (!consumed && watchErr == nil) {
		return errRedisTokenCASMismatch
	}
	return watchErr
}

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
			if err := redisClient.Set(ctx, userKey, token, 15*time.Minute).Err(); err == nil {
				return token, nil
			}
			// 避免出现 tokenKey 已写入但 userKey 缺失的不一致状态。
			_ = redisClient.Del(ctx, tokenKey).Err()
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
			uid, parseErr := strconv.ParseUint(uidStr, 10, 64)
			if parseErr == nil {
				userKey := RedisKey("password_reset", "user", strconv.FormatUint(uid, 10))
				casErr := verifyAndConsumeRedisTokenPair(ctx, redisClient, tokenKey, userKey, token, uidStr)
				if casErr == nil {
					return uint(uid), true
				}

				// 比对失败或并发竞争时，仅清理当前 tokenKey，避免误删新 token 对应的 userKey。
				if errors.Is(casErr, errRedisTokenCASMismatch) {
					_ = redisClient.Del(ctx, tokenKey).Err()
					return 0, false
				}

				return 0, false
			}
			_ = redisClient.Del(ctx, tokenKey).Err()
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

// GenerateEmailChangeToken 生成修改邮箱 Token，有效期 30 分钟。
func GenerateEmailChangeToken(userID uint, oldEmail, newEmail string) (string, error) {
	// 使用 crypto/rand 生成 32 字节的高熵随机字符串 (64字符Hex)
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := hex.EncodeToString(b)

	changeToken := EmailChangeToken{
		UserID:    userID,
		Token:     token,
		OldEmail:  oldEmail,
		NewEmail:  newEmail,
		ExpiresAt: time.Now().Add(30 * time.Minute),
	}

	if redisClient := GetRedisClient(); redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		// 保证一个用户只有一个有效 token
		userKey := RedisKey("email_change", "user", strconv.FormatUint(uint64(userID), 10))
		if oldToken, err := redisClient.Get(ctx, userKey).Result(); err == nil && oldToken != "" {
			oldTokenKey := RedisKey("email_change", "token", oldToken)
			_ = redisClient.Del(ctx, oldTokenKey).Err()
		}

		payload, err := json.Marshal(emailChangeRedisPayload{
			UserID:   userID,
			OldEmail: oldEmail,
			NewEmail: newEmail,
		})
		if err != nil {
			return "", err
		}

		tokenKey := RedisKey("email_change", "token", token)
		if err := redisClient.Set(ctx, tokenKey, payload, 30*time.Minute).Err(); err == nil {
			if err := redisClient.Set(ctx, userKey, token, 30*time.Minute).Err(); err == nil {
				return token, nil
			}
			// 避免出现 tokenKey 已写入但 userKey 缺失的不一致状态。
			_ = redisClient.Del(ctx, tokenKey).Err()
		}
	}

	// 存储（覆盖之前的）
	emailChangeStore.Store(userID, changeToken)
	return token, nil
}

// VerifyEmailChangeToken 验证并消费修改邮箱 Token。
func VerifyEmailChangeToken(token string) (*EmailChangeToken, bool) {
	if token == "" {
		return nil, false
	}

	if redisClient := GetRedisClient(); redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

		tokenKey := RedisKey("email_change", "token", token)
		raw, err := redisClient.Get(ctx, tokenKey).Result()
		if err == nil && raw != "" {
			var payload emailChangeRedisPayload
			if err := json.Unmarshal([]byte(raw), &payload); err != nil || payload.UserID == 0 {
				_ = redisClient.Del(ctx, tokenKey).Err()
				return nil, false
			}

			userKey := RedisKey("email_change", "user", strconv.FormatUint(uint64(payload.UserID), 10))
			casErr := verifyAndConsumeRedisTokenPair(ctx, redisClient, tokenKey, userKey, token, raw)
			if casErr == nil {
				return &EmailChangeToken{
					UserID:   payload.UserID,
					OldEmail: payload.OldEmail,
					NewEmail: payload.NewEmail,
				}, true
			}

			// 比对失败或并发竞争时，仅清理当前 tokenKey，避免误删新 token 对应的 userKey。
			if errors.Is(casErr, errRedisTokenCASMismatch) {
				_ = redisClient.Del(ctx, tokenKey).Err()
				return nil, false
			}
			return nil, false
		}
	}

	var foundToken *EmailChangeToken
	var valid bool

	// 遍历 Map 查找 Token
	emailChangeStore.Range(func(key, value interface{}) bool {
		changeToken, ok := value.(EmailChangeToken)
		if !ok {
			return true
		}

		if changeToken.Token == token {
			// 找到 Token，无论是否过期，都先删除以保证一次性使用。
			emailChangeStore.Delete(key)

			if time.Now().Before(changeToken.ExpiresAt) {
				copyToken := changeToken
				foundToken = &copyToken
				valid = true
			}
			return false // 停止遍历
		}

		// 顺便清理其他已过期的 Token (惰性清理)
		if time.Now().After(changeToken.ExpiresAt) {
			emailChangeStore.Delete(key)
		}
		return true
	})

	if valid {
		return foundToken, true
	}

	return nil, false
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
		log.Printf("Warning: Failed to delete avatar directory for user %d: %v\n", userID, err)
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
			log.Printf("Warning: Skip unsafe image path for user %d (%s): %v\n", userID, img.Path, secureErr)
			continue
		}

		if err := os.Remove(fullPath); err != nil {
			if !os.IsNotExist(err) {
				log.Printf("Warning: Failed to delete image file %s: %v\n", fullPath, err)
			}
		}
	}

	return nil
}
