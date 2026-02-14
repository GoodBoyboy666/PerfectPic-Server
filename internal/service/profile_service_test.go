package service

import (
	"testing"

	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/utils"

	"golang.org/x/crypto/bcrypt"
)

// 测试内容：验证用户资料查询返回完整字段。
func TestGetUserProfile(t *testing.T) {
	setupTestDB(t)

	q := int64(123)
	u := model.User{
		Username:     "alice",
		Password:     "x",
		Status:       1,
		Email:        "alice@example.com",
		Admin:        true,
		Avatar:       "a.png",
		StorageQuota: &q,
		StorageUsed:  10,
	}
	_ = db.DB.Create(&u).Error

	profile, err := GetUserProfile(u.ID)
	if err != nil {
		t.Fatalf("GetUserProfile: %v", err)
	}
	if profile.Username != "alice" || profile.Admin != true || profile.Avatar != "a.png" || profile.StorageUsed != 10 {
		t.Fatalf("非预期 profile: %+v", profile)
	}
}

// 测试内容：验证用户名更新的校验、冲突提示与成功后 token 生成。
func TestUpdateUsernameAndGenerateToken(t *testing.T) {
	setupTestDB(t)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "a@example.com"}
	_ = db.DB.Create(&u).Error

	token, msg, err := UpdateUsernameAndGenerateToken(u.ID, "ab", false)
	if err != nil || msg == "" || token != "" {
		t.Fatalf("期望 validation msg，实际为 token=%q msg=%q err=%v", token, msg, err)
	}

	u2 := model.User{Username: "bobby", Password: string(hashed), Status: 1, Email: "b@example.com"}
	_ = db.DB.Create(&u2).Error
	_, msg, err = UpdateUsernameAndGenerateToken(u.ID, "bobby", false)
	if err != nil || msg != "用户名已存在" {
		t.Fatalf("期望 conflict msg，实际为 msg=%q err=%v", msg, err)
	}

	token, msg, err = UpdateUsernameAndGenerateToken(u.ID, "alice2", true)
	if err != nil || msg != "" || token == "" {
		t.Fatalf("期望 success，实际为 token=%q msg=%q err=%v", token, msg, err)
	}
	claims, err := utils.ParseLoginToken(token)
	if err != nil {
		t.Fatalf("ParseLoginToken: %v", err)
	}
	if claims.Username != "alice2" || !claims.Admin {
		t.Fatalf("非预期 claims: %+v", claims)
	}
}

// 测试内容：验证通过旧密码更新密码的校验与成功路径。
func TestUpdatePasswordByOldPassword(t *testing.T) {
	setupTestDB(t)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "a@example.com"}
	_ = db.DB.Create(&u).Error

	msg, err := UpdatePasswordByOldPassword(u.ID, "abc12345", "short")
	if err != nil || msg == "" {
		t.Fatalf("期望 validation msg，实际为 msg=%q err=%v", msg, err)
	}

	msg, err = UpdatePasswordByOldPassword(u.ID, "wrong", "abc123456")
	if err != nil || msg != "旧密码错误" {
		t.Fatalf("期望 old password 错误，实际为 msg=%q err=%v", msg, err)
	}

	msg, err = UpdatePasswordByOldPassword(u.ID, "abc12345", "abc123456")
	if err != nil || msg != "" {
		t.Fatalf("期望 success，实际为 msg=%q err=%v", msg, err)
	}

	var got model.User
	_ = db.DB.First(&got, u.ID).Error
	if bcrypt.CompareHashAndPassword([]byte(got.Password), []byte("abc123456")) != nil {
		t.Fatalf("期望 password to be updated")
	}
}

// 测试内容：验证请求邮箱变更的校验、冲突提示与成功路径。
func TestRequestEmailChange(t *testing.T) {
	setupTestDB(t)

	// 确保 base_url 存在以覆盖 URL 规范化。
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigBaseURL, Value: "http://localhost/"}).Error
	ClearCache()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "a@example.com"}
	_ = db.DB.Create(&u).Error

	msg, err := RequestEmailChange(u.ID, "abc12345", "bad-email")
	if err != nil || msg == "" {
		t.Fatalf("期望 validation msg，实际为 msg=%q err=%v", msg, err)
	}

	msg, err = RequestEmailChange(u.ID, "wrong", "new@example.com")
	if err != nil || msg != "密码错误" {
		t.Fatalf("期望 password 错误，实际为 msg=%q err=%v", msg, err)
	}

	msg, err = RequestEmailChange(u.ID, "abc12345", "a@example.com")
	if err != nil || msg != "新邮箱不能与当前邮箱相同" {
		t.Fatalf("期望 same email msg，实际为 msg=%q err=%v", msg, err)
	}

	u2 := model.User{Username: "bob", Password: string(hashed), Status: 1, Email: "taken@example.com"}
	_ = db.DB.Create(&u2).Error
	msg, err = RequestEmailChange(u.ID, "abc12345", "taken@example.com")
	if err != nil || msg != "该邮箱已被使用" {
		t.Fatalf("期望 taken msg，实际为 msg=%q err=%v", msg, err)
	}

	msg, err = RequestEmailChange(u.ID, "abc12345", "new@example.com")
	if err != nil || msg != "" {
		t.Fatalf("期望 success，实际为 msg=%q err=%v", msg, err)
	}
}
