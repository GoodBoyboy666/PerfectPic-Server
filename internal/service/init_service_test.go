package service

import (
	"testing"

	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"

	"golang.org/x/crypto/bcrypt"
)

// 测试内容：验证系统初始化流程会创建管理员并更新初始化状态。
func TestInitializeSystemAndIsSystemInitialized(t *testing.T) {
	setupTestDB(t)

	// 创建默认设置行，使 InitializeSystem 的 Update() 命中真实行。
	InitializeSettings()
	ClearCache()

	if IsSystemInitialized() {
		t.Fatalf("期望 system to be uninitialized when allow_init is true")
	}

	payload := InitPayload{
		Username:        "admin",
		Password:        "abc12345",
		SiteName:        "MySite",
		SiteDescription: "Desc",
	}
	if err := InitializeSystem(payload); err != nil {
		t.Fatalf("InitializeSystem: %v", err)
	}

	if !IsSystemInitialized() {
		t.Fatalf("期望 system to be initialized after InitializeSystem")
	}

	var s model.Setting
	_ = db.DB.Where("key = ?", consts.ConfigSiteName).First(&s).Error
	if s.Value != "MySite" {
		t.Fatalf("期望 site name updated，实际为 %q", s.Value)
	}

	var u model.User
	if err := db.DB.Where("username = ?", "admin").First(&u).Error; err != nil {
		t.Fatalf("期望 admin user created: %v", err)
	}
	if !u.Admin {
		t.Fatalf("期望 admin flag true")
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte("abc12345")) != nil {
		t.Fatalf("期望 password to be hashed and match")
	}
}
