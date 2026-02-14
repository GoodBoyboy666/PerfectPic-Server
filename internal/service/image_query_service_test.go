package service

import (
	"strconv"
	"testing"

	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"

	"gorm.io/gorm"
)

func TestNormalizePagination(t *testing.T) {
	p, ps := normalizePagination(0, 0)
	if p != 1 || ps != 10 {
		t.Fatalf("expected defaults 1/10, got %d/%d", p, ps)
	}
	p, ps = normalizePagination(2, 5)
	if p != 2 || ps != 5 {
		t.Fatalf("expected 2/5, got %d/%d", p, ps)
	}
}

func TestListUserImages_FiltersAndPaging(t *testing.T) {
	setupTestDB(t)

	u := model.User{Username: "u1", Password: "x", Status: 1, Email: "u1@example.com"}
	if err := db.DB.Create(&u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	img1 := model.Image{Filename: "cat.png", Path: "2026/02/13/cat.png", Size: 1, Width: 1, Height: 1, MimeType: ".png", UploadedAt: 1, UserID: u.ID}
	img2 := model.Image{Filename: "dog.png", Path: "2026/02/13/dog.png", Size: 1, Width: 1, Height: 1, MimeType: ".png", UploadedAt: 2, UserID: u.ID}
	_ = db.DB.Create(&img1).Error
	_ = db.DB.Create(&img2).Error

	list, total, page, pageSize, err := ListUserImages(UserImageListParams{
		PaginationQuery: PaginationQuery{Page: 1, PageSize: 10},
		UserID:          u.ID,
		Filename:        "cat",
	})
	if err != nil {
		t.Fatalf("ListUserImages: %v", err)
	}
	if total != 1 || page != 1 || pageSize != 10 || len(list) != 1 {
		t.Fatalf("unexpected result: total=%d page=%d pageSize=%d len=%d", total, page, pageSize, len(list))
	}
	if list[0].Filename != "cat.png" {
		t.Fatalf("expected cat.png, got %q", list[0].Filename)
	}
}

func TestGetUserOwnedImage(t *testing.T) {
	setupTestDB(t)

	u := model.User{Username: "u1", Password: "x", Status: 1, Email: "u1@example.com"}
	_ = db.DB.Create(&u).Error
	img := model.Image{Filename: "a.png", Path: "2026/02/13/a.png", Size: 1, Width: 1, Height: 1, MimeType: ".png", UploadedAt: 1, UserID: u.ID}
	_ = db.DB.Create(&img).Error

	got, err := GetUserOwnedImage("1", u.ID)
	if err != nil {
		t.Fatalf("GetUserOwnedImage: %v", err)
	}
	if got.ID != img.ID {
		t.Fatalf("expected image id %d, got %d", img.ID, got.ID)
	}

	_, err = GetUserOwnedImage("1", u.ID+1)
	if err == nil {
		t.Fatalf("expected error for non-owned image")
	}
}

func TestGetUserImageCountAndBatchGetters(t *testing.T) {
	setupTestDB(t)

	u := model.User{Username: "u1", Password: "x", Status: 1, Email: "u1@example.com"}
	_ = db.DB.Create(&u).Error

	img1 := model.Image{Filename: "a.png", Path: "2026/02/13/a.png", Size: 1, Width: 1, Height: 1, MimeType: ".png", UploadedAt: 1, UserID: u.ID}
	img2 := model.Image{Filename: "b.png", Path: "2026/02/13/b.png", Size: 1, Width: 1, Height: 1, MimeType: ".png", UploadedAt: 1, UserID: u.ID}
	_ = db.DB.Create(&img1).Error
	_ = db.DB.Create(&img2).Error

	cnt, err := GetUserImageCount(u.ID)
	if err != nil {
		t.Fatalf("GetUserImageCount: %v", err)
	}
	if cnt != 2 {
		t.Fatalf("expected 2, got %d", cnt)
	}

	images, err := GetImagesByIDsForUser([]uint{img1.ID, img2.ID}, u.ID)
	if err != nil || len(images) != 2 {
		t.Fatalf("GetImagesByIDsForUser: err=%v len=%d", err, len(images))
	}

	got, err := GetImageByIDForAdmin(strconv.FormatUint(uint64(img1.ID), 10))
	if err != nil {
		t.Fatalf("GetImageByIDForAdmin: %v", err)
	}
	if got.ID != img1.ID {
		t.Fatalf("unexpected image id")
	}

	images2, err := GetImagesByIDsForAdmin([]uint{img1.ID, img2.ID})
	if err != nil || len(images2) != 2 {
		t.Fatalf("GetImagesByIDsForAdmin: err=%v len=%d", err, len(images2))
	}
}

func TestListImagesForAdmin_FiltersByUsername(t *testing.T) {
	setupTestDB(t)

	u1 := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com"}
	u2 := model.User{Username: "bob", Password: "x", Status: 1, Email: "b@example.com"}
	_ = db.DB.Create(&u1).Error
	_ = db.DB.Create(&u2).Error

	_ = db.DB.Create(&model.Image{Filename: "a.png", Path: "2026/02/13/a.png", Size: 1, Width: 1, Height: 1, MimeType: ".png", UploadedAt: 1, UserID: u1.ID}).Error
	_ = db.DB.Create(&model.Image{Filename: "b.png", Path: "2026/02/13/b.png", Size: 1, Width: 1, Height: 1, MimeType: ".png", UploadedAt: 1, UserID: u2.ID}).Error

	images, total, _, _, err := ListImagesForAdmin(AdminImageListParams{
		PaginationQuery: PaginationQuery{Page: 1, PageSize: 10},
		Username:        "ali",
	})
	if err != nil {
		t.Fatalf("ListImagesForAdmin: %v", err)
	}
	if total != 1 || len(images) != 1 {
		t.Fatalf("expected 1 image, got total=%d len=%d", total, len(images))
	}
	if images[0].User.Username != "alice" {
		t.Fatalf("expected preload user alice, got %q", images[0].User.Username)
	}
}

func TestIsRecordNotFound(t *testing.T) {
	if !IsRecordNotFound(gorm.ErrRecordNotFound) {
		t.Fatalf("expected true")
	}
}
