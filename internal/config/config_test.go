package config

import (
	"os"
	"testing"
)

// 测试内容：验证初始化配置会设置默认值并写入可用的配置目录。
func TestInitConfig_SetsDefaults(t *testing.T) {
	dir := t.TempDir()

	// 确保不在 release 模式（release 模式下不安全的 secret 可能导致 fatal）。
	t.Setenv("PERFECT_PIC_SERVER_MODE", "debug")
	t.Setenv("PERFECT_PIC_JWT_SECRET", "")

	InitConfig(dir)

	cfg := Get()
	if cfg.Server.Port == "" {
		t.Fatalf("期望 default server.port to be set")
	}
	if cfg.JWT.Secret == "" {
		t.Fatalf("期望 JWT secret to be set in non-release mode")
	}
	if GetConfigDir() != dir {
		t.Fatalf("期望 config dir %q，实际为 %q", dir, GetConfigDir())
	}

	// 写入一个配置文件名以确保目录可写（测试的基本健全性检查）。
	if err := os.WriteFile(dir+string(os.PathSeparator)+"_test_write", []byte("ok"), 0644); err != nil {
		t.Fatalf("期望 temp config dir to be writable: %v", err)
	}
}
