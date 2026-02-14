package middleware

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

// 测试内容：验证固定间隔限流会拦截同一来源的第二次请求。
func TestIntervalRateMiddleware_BlocksSecondRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	r := gin.New()
	r.POST("/x", IntervalRateMiddleware(10*time.Second), func(c *gin.Context) { c.Status(http.StatusOK) })

	req1 := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader([]byte("a")))
	req1.RemoteAddr = "1.2.3.4:1111"
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, req1)
	if w1.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w1.Code)
	}

	req2 := httptest.NewRequest(http.MethodPost, "/x", bytes.NewReader([]byte("a")))
	req2.RemoteAddr = "1.2.3.4:1111"
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, req2)
	if w2.Code != http.StatusTooManyRequests {
		t.Fatalf("期望 429，实际为 %d", w2.Code)
	}
}
