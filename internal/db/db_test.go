package db

import (
	"os"
	"path/filepath"
	"testing"

	"perfect-pic-server/internal/config"
	"perfect-pic-server/internal/model"
)

// 测试内容：验证使用 sqlite 临时文件初始化数据库并创建核心表。
func TestInitDB_SQLiteTempFile(t *testing.T) {
	tmp := t.TempDir()
	cfgDir := filepath.Join(tmp, "cfg")
	if err := os.MkdirAll(cfgDir, 0755); err != nil {
		t.Fatalf("创建配置目录失败: %v", err)
	}

	dbFile := filepath.Join(tmp, "db", "test.db")
	t.Setenv("PERFECT_PIC_SERVER_MODE", "debug")
	t.Setenv("PERFECT_PIC_DATABASE_TYPE", "sqlite")
	t.Setenv("PERFECT_PIC_DATABASE_FILENAME", dbFile)

	config.InitConfigWithoutWatch(cfgDir)
	InitDB()

	if DB == nil {
		t.Fatalf("期望 DB to be initialized")
	}
	if !DB.Migrator().HasTable(&model.User{}) {
		t.Fatalf("期望 users table to exist")
	}
	if !DB.Migrator().HasTable(&model.Setting{}) {
		t.Fatalf("期望 settings table to exist")
	}
	if !DB.Migrator().HasTable(&model.Image{}) {
		t.Fatalf("期望 images table to exist")
	}

	sqlDB, err := DB.DB()
	if err == nil {
		_ = sqlDB.Close()
	}
}
