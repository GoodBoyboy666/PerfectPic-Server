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

	// Upload one image.
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
		t.Fatalf("upload expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}

	var uploadResp struct {
		ID  uint   `json:"id"`
		URL string `json:"url"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &uploadResp)
	if uploadResp.ID == 0 || uploadResp.URL == "" {
		t.Fatalf("unexpected upload resp: %+v", uploadResp)
	}

	// List images.
	rec2 := httptest.NewRecorder()
	r.ServeHTTP(rec2, httptest.NewRequest(http.MethodGet, "/images?page=1&page_size=10", nil))
	if rec2.Code != http.StatusOK {
		t.Fatalf("list expected 200, got %d body=%s", rec2.Code, rec2.Body.String())
	}

	// Resolve physical file path before deletion.
	var img model.Image
	if err := db.DB.First(&img, uploadResp.ID).Error; err != nil {
		t.Fatalf("load image: %v", err)
	}
	full := filepath.Join("uploads", "imgs", filepath.FromSlash(img.Path))
	if _, err := os.Stat(full); err != nil {
		t.Fatalf("expected file exists: %v", err)
	}

	// Delete image.
	rec3 := httptest.NewRecorder()
	r.ServeHTTP(rec3, httptest.NewRequest(http.MethodDelete, "/images/"+strconv.FormatUint(uint64(uploadResp.ID), 10), nil))
	if rec3.Code != http.StatusOK {
		t.Fatalf("delete expected 200, got %d body=%s", rec3.Code, rec3.Body.String())
	}
	if _, err := os.Stat(full); !os.IsNotExist(err) {
		t.Fatalf("expected file deleted, err=%v", err)
	}
}

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
			t.Fatalf("upload expected 200, got %d body=%s", rec.Code, rec.Body.String())
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
		t.Fatalf("batch delete expected 200, got %d body=%s", rec.Code, rec.Body.String())
	}
}

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
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}

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
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}

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
		t.Fatalf("expected 403, got %d body=%s", w.Code, w.Body.String())
	}
}

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
		t.Fatalf("expected 400, got %d body=%s", w.Code, w.Body.String())
	}
}

func TestBatchDeleteMyImagesHandler_Errors(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com"}
	_ = db.DB.Create(&u).Error

	r := gin.New()
	r.DELETE("/images/batch", func(c *gin.Context) { c.Set("id", u.ID); c.Next() }, BatchDeleteMyImages)

	// bind error
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodDelete, "/images/batch", bytes.NewReader([]byte("{bad"))))
	if w1.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w1.Code)
	}

	// empty ids
	body, _ := json.Marshal(gin.H{"ids": []uint{}})
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodDelete, "/images/batch", bytes.NewReader(body)))
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w2.Code)
	}

	// not found
	body2, _ := json.Marshal(gin.H{"ids": []uint{1}})
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, httptest.NewRequest(http.MethodDelete, "/images/batch", bytes.NewReader(body2)))
	if w3.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d body=%s", w3.Code, w3.Body.String())
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
