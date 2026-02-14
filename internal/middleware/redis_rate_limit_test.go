package middleware

import (
	"testing"
	"time"

	"github.com/redis/go-redis/v9"
)

// 测试内容：验证禁用参数下 Redis 限流直接放行。
func TestAllowByRedisRateLimit_DisabledReturnsOK(t *testing.T) {
	ok, err := allowByRedisRateLimit(nil, "rate", "rps", "burst", "1.2.3.4", 0, 1)
	if err != nil || !ok {
		t.Fatalf("期望 ok when disabled，实际为 ok=%v err=%v", ok, err)
	}
	ok, err = allowByRedisRateLimit(nil, "rate", "rps", "burst", "1.2.3.4", 1, 0)
	if err != nil || !ok {
		t.Fatalf("期望 ok when disabled，实际为 ok=%v err=%v", ok, err)
	}
}

// 测试内容：验证 Redis 不可用时速率限流返回错误。
func TestAllowByRedisRateLimit_UnavailableRedisReturnsError(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 50 * time.Millisecond,
	})
	defer func() { _ = client.Close() }()

	ok, err := allowByRedisRateLimit(client, "rate", "rps", "burst", "1.2.3.4", 1, 1)
	if err == nil || ok {
		t.Fatalf("期望 redis 错误，实际为 ok=%v err=%v", ok, err)
	}
}

// 测试内容：验证 Redis 不可用时间隔限流返回错误。
func TestAllowByRedisInterval_UnavailableRedisReturnsError(t *testing.T) {
	client := redis.NewClient(&redis.Options{
		Addr:        "127.0.0.1:1",
		DialTimeout: 50 * time.Millisecond,
	})
	defer func() { _ = client.Close() }()

	ok, err := allowByRedisInterval(client, "interval", "1.2.3.4", 2*time.Second)
	if err == nil || ok {
		t.Fatalf("期望 redis 错误，实际为 ok=%v err=%v", ok, err)
	}
}
