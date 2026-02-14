package middleware

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/service"

	"github.com/gin-gonic/gin"
)

func TestUploadBodyLimitMiddleware_RejectsTooLarge(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	// 1MB limit.
	if err := db.DB.Save(&model.Setting{Key: consts.ConfigMaxUploadSize, Value: "1"}).Error; err != nil {
		t.Fatalf("set setting: %v", err)
	}
	service.ClearCache()

	r := gin.New()
	r.POST("/upload", UploadBodyLimitMiddleware(), func(c *gin.Context) { c.Status(http.StatusOK) })

	payload := bytes.Repeat([]byte("a"), 2*1024*1024)
	req := httptest.NewRequest(http.MethodPost, "/upload", bytes.NewReader(payload))
	req.ContentLength = int64(len(payload))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", w.Code)
	}
}

func TestBodyLimitMiddleware_LimitsNonUploadRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	// 1MB limit
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigMaxRequestBodySize, Value: "1"}).Error
	service.ClearCache()

	r := gin.New()
	r.POST("/x", BodyLimitMiddleware(), func(c *gin.Context) {
		_, err := io.ReadAll(c.Request.Body)
		if err != nil {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"err": err.Error()})
			return
		}
		c.Status(http.StatusOK)
	})

	payload := bytes.Repeat([]byte("a"), 2*1024*1024)
	req := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader(payload))
	req.ContentLength = int64(len(payload))
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d body=%s", w.Code, w.Body.String())
	}
}
