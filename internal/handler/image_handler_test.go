package handler

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/testutils"

	"github.com/gin-gonic/gin"
)

// 测试内容：验证上传、列表与删除图片接口的完整流程及文件落盘行为。
func TestUploadAndListAndDeleteImagesHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com"}
	_ = db.DB.Create(&u).Error

	r := gin.New()
	r.POST("/upload", func(c *gin.Context) { c.Set("id", u.ID); c.Next() }, UploadImage)
	r.GET("/images", func(c *gin.Context) { c.Set("id", u.ID); c.Next() }, GetMyImages)
	r.DELETE("/images/:id", func(c *gin.Context) { c.Set("id", u.ID); c.Next() }, DeleteMyImage)

	// 上传一张图片。
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, _ := w.CreateFormFile("file", "a.png")
	_, _ = part.Write(testutils.MinimalPNG())
	_ = w.Close()

	req := httptest.NewRequest(http.MethodPost, "/upload", &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("upload 期望 200，实际为 %d body=%s", rec.Code, rec.Body.String())
	}

	var uploadResp struct {
		ID  uint   `json:"id"`
		URL string `json:"url"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &uploadResp)
	if uploadResp.ID == 0 || uploadResp.URL == "" {
		t.Fatalf("非预期 upload resp: %+v", uploadResp)
	}

	// 列出图片。
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/images?page=1&page_size=10", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("list 期望 200，实际为 %d body=%s", rec2.Code, rec2.Body.String())
	}

	// 删除前解析物理文件路径。
	var img model.Image
	if err := db.DB.First(&img, uploadResp.ID).Error; err != nil {
		t.Fatalf("加载图片失败: %v", err)
	}
	full := filepath.Join("uploads", "imgs", filepath.FromSlash(img.Path))
	if _, err := os.Stat(full); err != nil {
		t.Fatalf("期望 file exists: %v", err)
	}

	// 删除图片。
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, httptest.NewRequest(http.MethodDelete, "/images/"+strconv.FormatUint(uint64(uploadResp.ID), 10), nil))
	if rec3.Code != http.StatusOK {
		t.Fatalf("delete 期望 200，实际为 %d body=%s", rec3.Code, rec3.Body.String())
	}
	if _, err := os.Stat(full); !os.IsNotExist(err) {
		t.Fatalf("期望 file deleted, err=%v", err)
	}
}

// 测试内容：验证批量删除图片接口可删除多张图片。
func TestBatchDeleteMyImagesHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com"}
	_ = db.DB.Create(&u).Error

	r := gin.New()
	r.POST("/upload", func(c *gin.Context) { c.Set("id", u.ID); c.Next() }, UploadImage)
	r.DELETE("/images/batch", func(c *gin.Context) { c.Set("id", u.ID); c.Next() }, BatchDeleteMyImages)

	upload := func() uint {
		var body bytes.Buffer
		w := multipart.NewWriter(&body)
		part, _ := w.CreateFormFile("file", "a.png")
		_, _ = part.Write(testutils.MinimalPNG())
		_ = w.Close()
		req := httptest.NewRequest(http.MethodPost, "/upload", &body)
		req.Header.Set("Content-Type", w.FormDataContentType())
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("upload 期望 200，实际为 %d body=%s", rec.Code, rec.Body.String())
		}
		var resp struct {
			ID uint `json:"id"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &resp)
		return resp.ID
	}

	id1 := upload()
	id2 := upload()

	body, _ := json.Marshal(gin.H{"ids": []uint{id1, id2}})
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, httptest.NewRequest(http.MethodDelete, "/images/batch", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("batch delete 期望 200，实际为 %d body=%s", rec.Code, rec.Body.String())
	}
}

// 测试内容：验证上传接口缺少文件时返回 400。
func TestUploadImageHandler_MissingFile(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com"}
	_ = db.DB.Create(&u).Error

	r := gin.New()
	r.POST("/upload", func(c *gin.Context) { c.Set("id", u.ID); c.Next() }, UploadImage)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/upload", nil))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证批量删除图片接口在 ID 数量超限时返回 400。
func TestBatchDeleteMyImagesHandler_TooManyIDs(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com"}
	_ = db.DB.Create(&u).Error

	r := gin.New()
	r.DELETE("/images/batch", func(c *gin.Context) { c.Set("id", u.ID); c.Next() }, BatchDeleteMyImages)

	ids := make([]uint, 51)
	for i := range ids {
		ids[i] = uint(i + 1)
	}
	body, _ := json.Marshal(gin.H{"ids": ids})

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodDelete, "/images/batch", bytes.NewReader(body)))
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证上传超出配额时返回 403。
func TestUploadImageHandler_QuotaExceededReturns403(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	q := int64(1)
	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com", StorageQuota: &q}
	_ = db.DB.Create(&u).Error

	r := gin.New()
	r.POST("/upload", func(c *gin.Context) { c.Set("id", u.ID); c.Next() }, UploadImage)

	req := newUploadRequest(t, "/upload", "a.png", testutils.MinimalPNG())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("期望 403，实际为 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证上传不支持扩展名时返回 400。
func TestUploadImageHandler_UnsupportedExtReturns400(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com"}
	_ = db.DB.Create(&u).Error

	r := gin.New()
	r.POST("/upload", func(c *gin.Context) { c.Set("id", u.ID); c.Next() }, UploadImage)

	req := newUploadRequest(t, "/upload", "a.exe", testutils.MinimalPNG())
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d body=%s", w.Code, w.Body.String())
	}
}

// 测试内容：验证批量删除接口的绑定错误、空列表与未找到分支。
func TestBatchDeleteMyImagesHandler_Errors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com"}
	_ = db.DB.Create(&u).Error

	r := gin.New()
	r.DELETE("/images/batch", func(c *gin.Context) { c.Set("id", u.ID); c.Next() }, BatchDeleteMyImages)

	// 绑定错误
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodDelete, "/images/batch", bytes.NewReader([]byte("{bad"))))
	if w1.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d", w1.Code)
	}

	// 空 id 列表
	body, _ := json.Marshal(gin.H{"ids": []uint{}})
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodDelete, "/images/batch", bytes.NewReader(body)))
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d", w2.Code)
	}

	// 未找到
	body2, _ := json.Marshal(gin.H{"ids": []uint{1}})
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, httptest.NewRequest(http.MethodDelete, "/images/batch", bytes.NewReader(body2)))
	if w3.Code != http.StatusNotFound {
		t.Fatalf("期望 404，实际为 %d body=%s", w3.Code, w3.Body.String())
	}
}

func newUploadRequest(t *testing.T, path, filename string, content []byte) *http.Request {
	t.Helper()

	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	part, err := w.CreateFormFile("file", filename)
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	_, _ = part.Write(content)
	_ = w.Close()

	req := httptest.NewRequest(http.MethodPost, path, &body)
	req.Header.Set("Content-Type", w.FormDataContentType())
	return req
}
