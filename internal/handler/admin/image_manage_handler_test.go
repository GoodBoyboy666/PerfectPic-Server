package admin

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"

	"github.com/gin-gonic/gin"
)

// 测试内容：验证管理员图片列表、单删与批删接口及文件清理行为。
func TestImageManageHandlers_ListAndDelete(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com"}
	_ = db.DB.Create(&u).Error

	// 创建图片物理文件和记录。
	imgRel := "2026/02/13/a.png"
	imgFile := filepath.Join("uploads", "imgs", filepath.FromSlash(imgRel))
	_ = os.MkdirAll(filepath.Dir(imgFile), 0755)
	_ = os.WriteFile(imgFile, []byte{0x89, 0x50, 0x4E, 0x47}, 0644)

	img := model.Image{Filename: "a.png", Path: imgRel, Size: 4, Width: 1, Height: 1, MimeType: ".png", UploadedAt: 1, UserID: u.ID}
	_ = db.DB.Create(&img).Error

	r := gin.New()
	r.GET("/images", GetImageList)
	r.DELETE("/images/:id", DeleteImage)
	r.DELETE("/images/batch", BatchDeleteImages)

	// 列表
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/images?page=1&page_size=10&username=ali", nil))
	if w1.Code != http.StatusOK {
		t.Fatalf("list 期望 200，实际为 %d body=%s", w1.Code, w1.Body.String())
	}

	// 删除单个
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodDelete, "/images/1", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("delete 期望 200，实际为 %d body=%s", w2.Code, w2.Body.String())
	}
	if _, err := os.Stat(imgFile); !os.IsNotExist(err) {
		t.Fatalf("期望 file removed, err=%v", err)
	}

	// 为批量删除重新创建两张图片
	imgFile1 := filepath.Join("uploads", "imgs", "2026", "02", "13", "b.png")
	imgFile2 := filepath.Join("uploads", "imgs", "2026", "02", "13", "c.png")
	_ = os.WriteFile(imgFile1, []byte{0x89, 0x50, 0x4E, 0x47}, 0644)
	_ = os.WriteFile(imgFile2, []byte{0x89, 0x50, 0x4E, 0x47}, 0644)
	imgB := model.Image{Filename: "b.png", Path: "2026/02/13/b.png", Size: 4, Width: 1, Height: 1, MimeType: ".png", UploadedAt: 1, UserID: u.ID}
	imgC := model.Image{Filename: "c.png", Path: "2026/02/13/c.png", Size: 4, Width: 1, Height: 1, MimeType: ".png", UploadedAt: 1, UserID: u.ID}
	_ = db.DB.Create(&imgB).Error
	_ = db.DB.Create(&imgC).Error

	body, _ := json.Marshal(gin.H{"ids": []uint{imgB.ID, imgC.ID}})
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, httptest.NewRequest(http.MethodDelete, "/images/batch", bytes.NewReader(body)))
	if w3.Code != http.StatusOK {
		t.Fatalf("batch delete 期望 200，实际为 %d body=%s", w3.Code, w3.Body.String())
	}
	if _, err := os.Stat(imgFile1); !os.IsNotExist(err) {
		t.Fatalf("期望 file1 removed, err=%v", err)
	}
	if _, err := os.Stat(imgFile2); !os.IsNotExist(err) {
		t.Fatalf("期望 file2 removed, err=%v", err)
	}
}

// 测试内容：验证管理员批量删除接口的绑定错误、空列表、超限与未找到分支。
func TestBatchDeleteImagesHandler_Errors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	r := gin.New()
	r.DELETE("/images/batch", BatchDeleteImages)

	// 绑定错误
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodDelete, "/images/batch", bytes.NewReader([]byte("{bad"))))
	if w1.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d body=%s", w1.Code, w1.Body.String())
	}

	// 空列表
	body, _ := json.Marshal(gin.H{"ids": []uint{}})
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodDelete, "/images/batch", bytes.NewReader(body)))
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d body=%s", w2.Code, w2.Body.String())
	}

	// 数量过多
	ids := make([]uint, 51)
	for i := range ids {
		ids[i] = uint(i + 1)
	}
	body2, _ := json.Marshal(gin.H{"ids": ids})
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, httptest.NewRequest(http.MethodDelete, "/images/batch", bytes.NewReader(body2)))
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d body=%s", w3.Code, w3.Body.String())
	}

	// 未找到
	body3, _ := json.Marshal(gin.H{"ids": []uint{1}})
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, httptest.NewRequest(http.MethodDelete, "/images/batch", bytes.NewReader(body3)))
	if w4.Code != http.StatusNotFound {
		t.Fatalf("期望 404，实际为 %d body=%s", w4.Code, w4.Body.String())
	}
}
