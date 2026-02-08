package middleware

import (
	"context"
	"net/http"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/service"
	"perfect-pic-server/internal/utils"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

var (
	// statusCache缓存用户状态，减少数据库查询
	// Key: userID (uint), Value: cachedStatus
	statusCache sync.Map
)

const statusCacheTTL = 1 * time.Minute

type cachedStatus struct {
	Status    int
	ExpiresAt time.Time
}

// ClearUserStatusCache 清除指定用户的状态缓存
func ClearUserStatusCache(userID uint) {
	statusCache.Delete(userID)

	if redisClient := service.GetRedisClient(); redisClient != nil {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		key := service.RedisKey("auth", "user_status", strconv.FormatUint(uint64(userID), 10))
		_ = redisClient.Del(ctx, key).Err()
	}
}

func JWTAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 获取请求头 Authorization
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "需要认证才能访问"})
			c.Abort()
			return
		}

		// 检查格式是否为 "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token 格式错误"})
			c.Abort()
			return
		}

		//解析 Token
		claims, err := utils.ParseLoginToken(parts[1])
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token 无效或已过期"})
			c.Abort()
			return
		}

		c.Set("id", claims.ID)
		c.Set("username", claims.Username)
		c.Set("admin", claims.Admin)
		c.Next()
	}
}

// UserStatusCheck 检查用户状态是否被封禁
func UserStatusCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("id")
		if !exists {
			// 如果没有上下文中的 id，说明 JWT 中间件可能未执行或失败但未 Abort（理论上不可能），或者顺序不对
			c.JSON(http.StatusUnauthorized, gin.H{"error": "未获取到用户信息"})
			c.Abort()
			return
		}

		uid, ok := userID.(uint)
		if !ok {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的用户ID类型"})
			c.Abort()
			return
		}

		var (
			currentStatus int
			statusFound   bool
		)

		// 优先从 Redis 读取
		if redisClient := service.GetRedisClient(); redisClient != nil {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()

			key := service.RedisKey("auth", "user_status", strconv.FormatUint(uint64(uid), 10))
			cachedStatusStr, err := redisClient.Get(ctx, key).Result()
			if err == nil {
				if parsedStatus, parseErr := strconv.Atoi(cachedStatusStr); parseErr == nil {
					currentStatus = parsedStatus
					statusFound = true
					statusCache.Store(uid, cachedStatus{
						Status:    currentStatus,
						ExpiresAt: time.Now().Add(statusCacheTTL),
					})
				}
			}
		}

		// Redis 未命中或不可用时，回退本地内存缓存
		if !statusFound {
			if val, ok := statusCache.Load(uid); ok {
				cached, typeOk := val.(cachedStatus)
				if typeOk {
					if time.Now().Before(cached.ExpiresAt) {
						currentStatus = cached.Status
						statusFound = true
					} else {
						statusCache.Delete(uid)
					}
				}
			}
		}

		// 如果缓存未命中或过期，查询数据库
		if !statusFound {
			var user model.User
			if err := db.DB.Select("status").First(&user, uid).Error; err != nil {
				c.JSON(http.StatusUnauthorized, gin.H{"error": "用户不存在"})
				c.Abort()
				return
			}
			currentStatus = user.Status

			// 写入缓存
			statusCache.Store(uid, cachedStatus{
				Status:    currentStatus,
				ExpiresAt: time.Now().Add(statusCacheTTL),
			})

			if redisClient := service.GetRedisClient(); redisClient != nil {
				ctx, cancel := context.WithTimeout(context.Background(), time.Second)
				defer cancel()

				key := service.RedisKey("auth", "user_status", strconv.FormatUint(uint64(uid), 10))
				_ = redisClient.Set(ctx, key, strconv.Itoa(currentStatus), statusCacheTTL).Err()
			}
		}

		if currentStatus == 2 {
			c.JSON(http.StatusForbidden, gin.H{"error": "账号已被封禁"})
			c.Abort()
			return
		}
		if currentStatus == 3 {
			c.JSON(http.StatusForbidden, gin.H{"error": "账号已停用"})
			c.Abort()
			return
		}

		c.Next()
	}
}

func AdminCheck() gin.HandlerFunc {
	return func(c *gin.Context) {
		value, exist := c.Get("admin")
		isAdmin, ok := value.(bool)
		if !exist || !ok || !isAdmin {
			c.JSON(http.StatusForbidden, gin.H{"error": "需要管理员权限才能访问"})
			c.Abort()
			return
		}
		c.Next()
	}
}
