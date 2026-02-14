package service

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/testutils"
)

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
		t.Fatalf("expected file deleted, err=%v", err)
	}

	var count int64
	_ = db.DB.Model(&model.Image{}).Count(&count).Error
	if count != 0 {
		t.Fatalf("expected image record deleted")
	}

	var got model.User
	_ = db.DB.First(&got, u.ID).Error
	if got.StorageUsed != 0 {
		t.Fatalf("expected storage_used 0, got %d", got.StorageUsed)
	}
}

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
		t.Fatalf("expected file1 deleted, err=%v", err)
	}
	if _, err := os.Stat(full2); !os.IsNotExist(err) {
		t.Fatalf("expected file2 deleted, err=%v", err)
	}

	var got model.User
	_ = db.DB.First(&got, u.ID).Error
	if got.StorageUsed != 0 {
		t.Fatalf("expected storage_used 0, got %d", got.StorageUsed)
	}
}

func TestUpdateAndRemoveUserAvatar(t *testing.T) {
	setupTestDB(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com", Avatar: "old.png"}
	_ = db.DB.Create(&u).Error

	// Create old avatar file
	oldPath := filepath.Join("uploads", "avatars", strconv.FormatUint(uint64(u.ID), 10), "old.png")
	_ = os.MkdirAll(filepath.Dir(oldPath), 0755)
	_ = os.WriteFile(oldPath, []byte("x"), 0644)

	fh := mustFileHeader(t, "a.png", testutils.MinimalPNG())
	newName, err := UpdateUserAvatar(&u, fh)
	if err != nil {
		t.Fatalf("UpdateUserAvatar: %v", err)
	}
	if newName == "" {
		t.Fatalf("expected new avatar filename")
	}
	if _, err := os.Stat(oldPath); !os.IsNotExist(err) {
		t.Fatalf("expected old avatar removed, err=%v", err)
	}

	var got model.User
	_ = db.DB.First(&got, u.ID).Error
	if got.Avatar == "" {
		t.Fatalf("expected avatar set in db")
	}

	avatarPath := filepath.Join("uploads", "avatars", strconv.FormatUint(uint64(u.ID), 10), got.Avatar)
	if _, err := os.Stat(avatarPath); err != nil {
		t.Fatalf("expected new avatar file exists: %v", err)
	}

	if err := RemoveUserAvatar(&got); err != nil {
		t.Fatalf("RemoveUserAvatar: %v", err)
	}
	var got2 model.User
	_ = db.DB.First(&got2, u.ID).Error
	if got2.Avatar != "" {
		t.Fatalf("expected avatar cleared, got %q", got2.Avatar)
	}
	if _, err := os.Stat(avatarPath); !os.IsNotExist(err) {
		t.Fatalf("expected avatar file removed, err=%v", err)
	}
}
