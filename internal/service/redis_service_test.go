package service

import (
	"testing"

	"github.com/redis/go-redis/v9"
)

// 测试内容：验证 Redis key 使用默认前缀拼接。
func TestRedisKey_DefaultPrefix(t *testing.T) {
	// TestMain 在未设置时使用默认前缀初始化配置。
	got := RedisKey("a", "b")
	if got != "perfect_pic:a:b" {
		t.Fatalf("非预期 key: %q", got)
	}
}

// 测试内容：验证无参数时返回仅包含前缀的 key。
func TestRedisKey_NoParts(t *testing.T) {
	if got := RedisKey(); got != "perfect_pic" {
		t.Fatalf("非预期 key: %q", got)
	}
}

// 测试内容：验证禁用 Redis 时获取客户端返回 nil。
func TestGetRedisClient_DisabledReturnsNil(t *testing.T) {
	// TestMain 将 redis 设为禁用；GetRedisClient 应保持为 nil。
	if c := GetRedisClient(); c != nil {
		t.Fatalf("期望为 nil redis client when disabled")
	}
}

// 测试内容：验证关闭 Redis 客户端在 nil 与非 nil 场景均可执行。
func TestCloseRedisClient(t *testing.T) {
	redisClient = nil
	if err := CloseRedisClient(); err != nil {
		t.Fatalf("期望为 nil，实际为 %v", err)
	}

	redisClient = redis.NewClient(&redis.Options{Addr: "127.0.0.1:1"})
	if err := CloseRedisClient(); err != nil {
		t.Fatalf("CloseRedisClient: %v", err)
	}
	redisClient = nil
}
