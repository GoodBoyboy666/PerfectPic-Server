package service

import (
	"os"
	"testing"

	"perfect-pic-server/internal/config"
)

// 测试内容：为 service 包测试初始化配置环境并在结束时清理。
func TestMain(m *testing.M) {
	// 为依赖配置的测试提供稳定默认值（JWT 过期时间、上传前缀等）。
	tmpDir, err := os.MkdirTemp("", "perfect-pic-config-*")
	if err != nil {
		panic(err)
	}

	_ = os.Setenv("PERFECT_PIC_SERVER_MODE", "debug")
	_ = os.Setenv("PERFECT_PIC_JWT_SECRET", "test_secret")
	_ = os.Setenv("PERFECT_PIC_REDIS_ENABLED", "false")
	config.InitConfig(tmpDir)

	code := m.Run()

	_ = os.RemoveAll(tmpDir)
	os.Exit(code)
}
