package service

import (
	"bytes"
	"mime/multipart"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/testutils"
)

// 测试内容：验证图片文件校验在合法图片时返回通过。
func TestValidateImageFile_OK(t *testing.T) {
	setupTestDB(t)

	fh := mustFileHeader(t, "a.png", testutils.MinimalPNG())
	ok, ext, err := ValidateImageFile(fh)
	if !ok || err != nil {
		t.Fatalf("期望 ok，实际为 ok=%v ext=%q err=%v", ok, ext, err)
	}
	if ext != ".png" {
		t.Fatalf("期望 .png ext，实际为 %q", ext)
	}
}

// 测试内容：验证不支持的文件扩展名会被拒绝。
func TestValidateImageFile_RejectsUnsupportedExt(t *testing.T) {
	setupTestDB(t)

	fh := mustFileHeader(t, "a.exe", testutils.MinimalPNG())
	ok, ext, err := ValidateImageFile(fh)
	if ok || err == nil {
		t.Fatalf("期望 failure，实际为 ok=%v ext=%q err=%v", ok, ext, err)
	}
	if ext != ".exe" {
		t.Fatalf("期望 ext to be .exe，实际为 %q", ext)
	}
}

// 测试内容：验证图片上传会写入文件、创建记录并更新用户存储使用量。
func TestProcessImageUpload_SavesFileAndCreatesRecord(t *testing.T) {
	setupTestDB(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatalf("切换工作目录失败: %v", err)
	}
	defer func() { _ = os.Chdir(oldwd) }()

	u := model.User{
		Username: "alice",
		Password: "x",
		Status:   1,
		Email:    "alice@example.com",
	}
	if err := db.DB.Create(&u).Error; err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}

	fh := mustFileHeader(t, "a.png", testutils.MinimalPNG())
	img, url, err := ProcessImageUpload(fh, u.ID)
	if err != nil {
		t.Fatalf("ProcessImageUpload 错误: %v", err)
	}
	if img == nil || img.ID == 0 {
		t.Fatalf("期望 image record to be created")
	}
	if !strings.HasSuffix(img.Filename, ".png") {
		t.Fatalf("期望 filename to end with .png，实际为 %q", img.Filename)
	}
	if !strings.HasPrefix(img.Path, "20") || !strings.HasSuffix(img.Path, ".png") {
		t.Fatalf("非预期 image path: %q", img.Path)
	}
	if !strings.HasPrefix(url, "/imgs/") {
		t.Fatalf("期望 url to start with /imgs/，实际为 %q", url)
	}

	// 物理文件应存在。
	full := filepath.Join("uploads", "imgs", filepath.FromSlash(img.Path))
	if _, err := os.Stat(full); err != nil {
		t.Fatalf("期望 uploaded file to exist at %q: %v", full, err)
	}

	// 已用存储应增加。
	var got model.User
	if err := db.DB.First(&got, u.ID).Error; err != nil {
		t.Fatalf("加载用户失败: %v", err)
	}
	if got.StorageUsed <= 0 {
		t.Fatalf("期望 storage_used to be increased，实际为 %d", got.StorageUsed)
	}
}

// 测试内容：验证超出配额时上传返回存储空间不足错误。
func TestProcessImageUpload_QuotaExceeded(t *testing.T) {
	setupTestDB(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	q := int64(1)
	u := model.User{
		Username:     "alice",
		Password:     "x",
		Status:       1,
		Email:        "alice@example.com",
		StorageQuota: &q,
	}
	_ = db.DB.Create(&u).Error

	fh := mustFileHeader(t, "a.png", testutils.MinimalPNG())
	_, _, err := ProcessImageUpload(fh, u.ID)
	if err == nil || !strings.Contains(err.Error(), "存储空间不足") {
		t.Fatalf("期望 quota 错误, got: %v", err)
	}
}

// 测试内容：验证删除图片会移除文件并同步更新存储占用。
func TestDeleteImage_RemovesFileAndUpdatesStorage(t *testing.T) {
	setupTestDB(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com", StorageUsed: 4}
	_ = db.DB.Create(&u).Error

	imgRel := "2026/02/13/a.png"
	full := filepath.Join("uploads", "imgs", filepath.FromSlash(imgRel))
	_ = os.MkdirAll(filepath.Dir(full), 0755)
	_ = os.WriteFile(full, []byte{0x89, 0x50, 0x4E, 0x47}, 0644)

	img := model.Image{Filename: "a.png", Path: imgRel, Size: 4, Width: 1, Height: 1, MimeType: ".png", UploadedAt: 1, UserID: u.ID}
	_ = db.DB.Create(&img).Error

	if err := DeleteImage(&img); err != nil {
		t.Fatalf("DeleteImage: %v", err)
	}
	if _, err := os.Stat(full); !os.IsNotExist(err) {
		t.Fatalf("期望 file deleted, err=%v", err)
	}

	var count int64
	_ = db.DB.Model(&model.Image{}).Count(&count).Error
	if count != 0 {
		t.Fatalf("期望 image record deleted")
	}

	var got model.User
	_ = db.DB.First(&got, u.ID).Error
	if got.StorageUsed != 0 {
		t.Fatalf("期望 storage_used 0，实际为 %d", got.StorageUsed)
	}
}

// 测试内容：验证批量删除图片会移除文件并更新存储占用。
func TestBatchDeleteImages_RemovesFilesAndUpdatesStorage(t *testing.T) {
	setupTestDB(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com", StorageUsed: 8}
	_ = db.DB.Create(&u).Error

	img1 := model.Image{Filename: "a.png", Path: "2026/02/13/a.png", Size: 4, Width: 1, Height: 1, MimeType: ".png", UploadedAt: 1, UserID: u.ID}
	img2 := model.Image{Filename: "b.png", Path: "2026/02/13/b.png", Size: 4, Width: 1, Height: 1, MimeType: ".png", UploadedAt: 1, UserID: u.ID}
	_ = db.DB.Create(&img1).Error
	_ = db.DB.Create(&img2).Error

	full1 := filepath.Join("uploads", "imgs", filepath.FromSlash(img1.Path))
	full2 := filepath.Join("uploads", "imgs", filepath.FromSlash(img2.Path))
	_ = os.MkdirAll(filepath.Dir(full1), 0755)
	_ = os.WriteFile(full1, []byte{0x89, 0x50, 0x4E, 0x47}, 0644)
	_ = os.WriteFile(full2, []byte{0x89, 0x50, 0x4E, 0x47}, 0644)

	if err := BatchDeleteImages([]model.Image{img1, img2}); err != nil {
		t.Fatalf("BatchDeleteImages: %v", err)
	}
	if _, err := os.Stat(full1); !os.IsNotExist(err) {
		t.Fatalf("期望 file1 deleted, err=%v", err)
	}
	if _, err := os.Stat(full2); !os.IsNotExist(err) {
		t.Fatalf("期望 file2 deleted, err=%v", err)
	}

	var got model.User
	_ = db.DB.First(&got, u.ID).Error
	if got.StorageUsed != 0 {
		t.Fatalf("期望 storage_used 0，实际为 %d", got.StorageUsed)
	}
}

// 测试内容：验证更新头像会替换旧文件，移除头像会清理记录与文件。
func TestUpdateAndRemoveUserAvatar(t *testing.T) {
	setupTestDB(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com", Avatar: "old.png"}
	_ = db.DB.Create(&u).Error

	// 创建旧头像文件
	oldPath := filepath.Join("uploads", "avatars", strconv.FormatUint(uint64(u.ID), 10), "old.png")
	_ = os.MkdirAll(filepath.Dir(oldPath), 0755)
	_ = os.WriteFile(oldPath, []byte("x"), 0644)

	fh := mustFileHeader(t, "a.png", testutils.MinimalPNG())
	newName, err := UpdateUserAvatar(&u, fh)
	if err != nil {
		t.Fatalf("UpdateUserAvatar: %v", err)
	}
	if newName == "" {
		t.Fatalf("期望 new avatar filename")
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("期望 old avatar removed, err=%v", err)
	}

	var got model.User
	_ = db.DB.First(&got, u.ID).Error
	if got.Avatar == "" {
		t.Fatalf("期望 avatar set in db")
	}

	avatarPath := filepath.Join("uploads", "avatars", strconv.FormatUint(uint64(u.ID), 10), got.Avatar)
	if _, err := os.Stat(avatarPath); err != nil {
		t.Fatalf("期望 new avatar file exists: %v", err)
	}

	if err := RemoveUserAvatar(&got); err != nil {
		t.Fatalf("RemoveUserAvatar: %v", err)
	}
	var got2 model.User
	_ = db.DB.First(&got2, u.ID).Error
	if got2.Avatar != "" {
		t.Fatalf("期望 avatar cleared，实际为 %q", got2.Avatar)
	}
	if _, err := os.Stat(avatarPath); !os.IsNotExist(err) {
		t.Fatalf("期望 avatar file removed, err=%v", err)
	}
}

func mustFileHeader(t *testing.T, filename string, content []byte) *multipart.FileHeader {
	t.Helper()

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("写入分段失败: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("关闭 writer 失败: %v", err)
	}

	req := httptest.NewRequest("POST", "http://example/upload", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	if err := req.ParseMultipartForm(int64(len(content)) + 1024); err != nil {
		t.Fatalf("ParseMultipartForm: %v", err)
	}

	fhs := req.MultipartForm.File["file"]
	if len(fhs) != 1 {
		t.Fatalf("期望 1 file header，实际为 %d", len(fhs))
	}
	return fhs[0]
}
