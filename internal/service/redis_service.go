package service

import (
	"context"
	"fmt"
	"log"
	"perfect-pic-server/internal/config"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	redisOnce   sync.Once
	redisClient *redis.Client
	redisReady  bool
)

// GetRedisClient 获取 Redis 客户端；当未启用或不可用时返回 nil。
func GetRedisClient() *redis.Client {
	redisOnce.Do(initRedisClient)
	if !redisReady {
		return nil
	}
	return redisClient
}

// RedisKey 基于配置前缀拼接 Redis 键名。
func RedisKey(parts ...string) string {
	cfg := config.Get()
	prefix := cfg.Redis.Prefix
	if prefix == "" {
		prefix = "perfect_pic"
	}
	if len(parts) == 0 {
		return prefix
	}
	key := prefix
	for _, p := range parts {
		key += ":" + p
	}
	return key
}

func initRedisClient() {
	cfg := config.Get()
	if !cfg.Redis.Enabled {
		redisReady = false
		return
	}

	client := redis.NewClient(&redis.Options{
		Addr:     cfg.Redis.Addr,
		Password: cfg.Redis.Password,
		DB:       cfg.Redis.DB,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		redisReady = false
		_ = client.Close()
		log.Printf("⚠️ Redis 不可用，降级为内存模式: %v", err)
		return
	}

	redisClient = client
	redisReady = true
	log.Printf("✅ Redis 已连接: %s (db=%d)", cfg.Redis.Addr, cfg.Redis.DB)
}

// CloseRedisClient 关闭 Redis 客户端连接。
func CloseRedisClient() error {
	if redisClient == nil {
		return nil
	}
	err := redisClient.Close()
	if err != nil {
		return fmt.Errorf("close redis failed: %w", err)
	}
	return nil
}
