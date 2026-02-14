package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"perfect-pic-server/internal/service"

	"github.com/gin-gonic/gin"
)

// 测试内容：验证初始化状态查询与首次初始化成功、二次初始化被禁止。
func TestInitHandlers_StateAndInit(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	// 确保默认设置存在，使 InitializeSystem 能更新到实际行。
	service.InitializeSettings()

	r := gin.New()
	r.GET("/init", GetInitState)
	r.POST("/init", Init)

	// 初始未初始化。
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/init", nil))
	if w1.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w1.Code)
	}

	body, _ := json.Marshal(gin.H{
		"username":         "admin_1",
		"password":         "abc12345",
		"site_name":        "MySite",
		"site_description": "Desc",
	})
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodPost, "/init", bytes.NewReader(body)))
	if w2.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d body=%s", w2.Code, w2.Body.String())
	}

	// 第二次初始化应被禁止。
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, httptest.NewRequest(http.MethodPost, "/init", bytes.NewReader(body)))
	if w3.Code != http.StatusForbidden {
		t.Fatalf("期望 403，实际为 %d body=%s", w3.Code, w3.Body.String())
	}
}
