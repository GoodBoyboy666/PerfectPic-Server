package service

import (
	"os"
	"path/filepath"
	"testing"

	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
)

// 测试内容：验证重置密码令牌可生成、可校验且为一次性使用。
func TestGenerateAndVerifyForgetPasswordToken_OneTimeUse(t *testing.T) {
	setupTestDB(t)
	resetPasswordResetStore()

	token, err := GenerateForgetPasswordToken(42)
	if err != nil {
		t.Fatalf("GenerateForgetPasswordToken: %v", err)
	}
	if len(token) != 64 {
		t.Fatalf("期望 64-char hex token，实际为 len=%d token=%q", len(token), token)
	}

	uid, ok := VerifyForgetPasswordToken(token)
	if !ok || uid != 42 {
		t.Fatalf("期望 valid token for uid=42，实际为 uid=%d ok=%v", uid, ok)
	}

	uid2, ok2 := VerifyForgetPasswordToken(token)
	if ok2 || uid2 != 0 {
		t.Fatalf("期望 one-time use token to be 无效 on second use，实际为 uid=%d ok=%v", uid2, ok2)
	}
}

// 测试内容：验证删除用户文件会移除头像目录和图片文件记录。
func TestDeleteUserFiles_RemovesAvatarDirAndImages(t *testing.T) {
	setupTestDB(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("切换工作目录失败: %v", err)
	}
	defer func() { _ = os.Chdir(oldwd) }()

	userID := uint(7)

	// 创建包含文件的头像目录。
	avatarDir := filepath.Join("uploads", "avatars", "7")
	if err := os.MkdirAll(avatarDir, 0755); err != nil {
		t.Fatalf("创建头像目录失败: %v", err)
	}
	if err := os.WriteFile(filepath.Join(avatarDir, "a.txt"), []byte("x"), 0644); err != nil {
		t.Fatalf("写入头像文件失败: %v", err)
	}

	// 创建图片记录和物理文件。
	imgRel := filepath.ToSlash(filepath.Join("2026", "02", "13", "x.png"))
	imgLocal := filepath.FromSlash(imgRel)
	imgFile := filepath.Join("uploads", "imgs", imgLocal)
	if err := os.MkdirAll(filepath.Dir(imgFile), 0755); err != nil {
		t.Fatalf("创建图片目录失败: %v", err)
	}
	if err := os.WriteFile(imgFile, []byte{0x89, 0x50, 0x4E, 0x47}, 0644); err != nil {
		t.Fatalf("写入图片文件失败: %v", err)
	}

	if err := db.DB.Create(&model.Image{
		Filename:   "x.png",
		Path:       imgRel,
		Size:       4,
		MimeType:   ".png",
		UploadedAt: 1,
		UserID:     userID,
		Width:      1,
		Height:     1,
	}).Error; err != nil {
		t.Fatalf("create image record: %v", err)
	}

	if err := DeleteUserFiles(userID); err != nil {
		t.Fatalf("DeleteUserFiles: %v", err)
	}

	if _, err := os.Stat(avatarDir); !os.IsNotExist(err) {
		t.Fatalf("期望 avatar dir to be removed, stat err=%v", err)
	}
	if _, err := os.Stat(imgFile); !os.IsNotExist(err) {
		t.Fatalf("期望 image file to be removed, stat err=%v", err)
	}
}

// 测试内容：验证默认存储配额读取与配置覆盖逻辑。
func TestGetSystemDefaultStorageQuota(t *testing.T) {
	setupTestDB(t)

	// 当设置缺失时应回退到 DefaultSettings 的默认值。
	if got := GetSystemDefaultStorageQuota(); got <= 0 {
		t.Fatalf("期望 positive default quota，实际为 %d", got)
	}

	// 覆盖为自定义值。
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigDefaultStorageQuota, Value: "123"}).Error
	ClearCache()
	if got := GetSystemDefaultStorageQuota(); got != 123 {
		t.Fatalf("期望 123，实际为 %d", got)
	}
}
