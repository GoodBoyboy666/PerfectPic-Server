package admin

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"

	"github.com/gin-gonic/gin"
)

// 测试内容：验证统计接口返回的图片数、用户数与存储占用。
func TestGetServerStats_ReturnsCounts(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	u := model.User{Username: "u1", Password: "x", Status: 1, Email: "u1@example.com"}
	if err := db.DB.Create(&u).Error; err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}
	_ = db.DB.Create(&model.Image{
		Filename:   "a.png",
		Path:       "2026/02/13/a.png",
		Size:       10,
		MimeType:   ".png",
		UploadedAt: 1,
		UserID:     u.ID,
		Width:      1,
		Height:     1,
	}).Error

	r := gin.New()
	r.GET("/stats", GetServerStats)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w.Code)
	}

	var resp struct {
		ImageCount   int64 `json:"image_count"`
		StorageUsage int64 `json:"storage_usage"`
		UserCount    int64 `json:"user_count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("解析失败: %v", err)
	}
	if resp.ImageCount != 1 || resp.UserCount != 1 || resp.StorageUsage != 10 {
		t.Fatalf("非预期 stats: %+v", resp)
	}
}
