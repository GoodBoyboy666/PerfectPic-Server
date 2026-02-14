package service

import (
	"testing"

	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
)

// 测试内容：验证用户名占用检测在是否包含已删除用户时的差异。
func TestIsUsernameTaken_IncludeDeleted(t *testing.T) {
	setupTestDB(t)

	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com"}
	if err := db.DB.Create(&u).Error; err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}
	if err := db.DB.Delete(&u).Error; err != nil {
		t.Fatalf("soft delete user: %v", err)
	}

	taken, err := IsUsernameTaken("alice", nil, false)
	if err != nil {
		t.Fatalf("IsUsernameTaken: %v", err)
	}
	if taken {
		t.Fatalf("期望 username not taken when exclude deleted")
	}

	taken2, err := IsUsernameTaken("alice", nil, true)
	if err != nil {
		t.Fatalf("IsUsernameTaken(includeDeleted): %v", err)
	}
	if !taken2 {
		t.Fatalf("期望 username taken when include deleted")
	}
}

// 测试内容：验证邮箱占用检测支持排除指定用户 ID。
func TestIsEmailTaken_ExcludeUserID(t *testing.T) {
	setupTestDB(t)

	u1 := model.User{Username: "a1", Password: "x", Status: 1, Email: "x@example.com"}
	u2 := model.User{Username: "a2", Password: "x", Status: 1, Email: "y@example.com"}
	_ = db.DB.Create(&u1).Error
	_ = db.DB.Create(&u2).Error

	exclude := u1.ID
	taken, err := IsEmailTaken("x@example.com", &exclude, true)
	if err != nil {
		t.Fatalf("IsEmailTaken: %v", err)
	}
	if taken {
		t.Fatalf("期望 email not taken when excluding matching user")
	}
}
