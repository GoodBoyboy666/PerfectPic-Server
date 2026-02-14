package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/utils"

	"github.com/gin-gonic/gin"
)

// 测试内容：验证缺少 Authorization 头时返回 401。
func TestJWTAuth_MissingHeaderUnauthorized(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/x", JWTAuth(), func(c *gin.Context) { c.Status(http.StatusOK) })

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际为 %d", w.Code)
	}
}

// 测试内容：验证有效登录令牌会在上下文中设置用户信息。
func TestJWTAuth_ValidTokenSetsContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/x", JWTAuth(), func(c *gin.Context) {
		id, _ := c.Get("id")
		username, _ := c.Get("username")
		admin, _ := c.Get("admin")
		if id != uint(1) || username != "alice" || admin != true {
			c.JSON(500, gin.H{"bad": true})
			return
		}
		c.Status(http.StatusOK)
	})

	token, err := utils.GenerateLoginToken(1, "alice", true, time.Hour)
	if err != nil {
		t.Fatalf("GenerateLoginToken: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w.Code)
	}
}

// 测试内容：验证被禁用用户状态会被拦截并返回 403。
func TestUserStatusCheck_BannedForbidden(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	resetStatusCache()

	u := model.User{Username: "alice", Password: "x", Status: 2, Email: "a@example.com"}
	if err := db.DB.Create(&u).Error; err != nil {
		t.Fatalf("创建用户失败: %v", err)
	}

	r := gin.New()
	r.GET("/x",
		func(c *gin.Context) { c.Set("id", u.ID); c.Next() },
		UserStatusCheck(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("期望 403，实际为 %d", w.Code)
	}
}

// 测试内容：验证正常用户状态通过检查并返回 200。
func TestUserStatusCheck_NormalOK(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	resetStatusCache()

	u := model.User{Username: "alice", Password: "x", Status: 1, Email: "a@example.com"}
	_ = db.DB.Create(&u).Error

	r := gin.New()
	r.GET("/x",
		func(c *gin.Context) { c.Set("id", u.ID); c.Next() },
		UserStatusCheck(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)

	req := httptest.NewRequest(http.MethodGet, "/x", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("期望 200，实际为 %d", w.Code)
	}
}

// 测试内容：验证缺失 id、类型错误、未找到用户与禁用状态的错误分支处理。
func TestUserStatusCheck_ErrorBranches(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)
	resetStatusCache()

	// 缺少 id
	r1 := gin.New()
	r1.GET("/x", UserStatusCheck(), func(c *gin.Context) { c.Status(http.StatusOK) })
	w1 := httptest.NewRecorder()
	r1.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w1.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际为 %d", w1.Code)
	}

	// id 类型错误
	r2 := gin.New()
	r2.GET("/x",
		func(c *gin.Context) { c.Set("id", "bad"); c.Next() },
		UserStatusCheck(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)
	w2 := httptest.NewRecorder()
	r2.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w2.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际为 %d", w2.Code)
	}

	// 用户未找到
	r3 := gin.New()
	r3.GET("/x",
		func(c *gin.Context) { c.Set("id", uint(999)); c.Next() },
		UserStatusCheck(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)
	w3 := httptest.NewRecorder()
	r3.ServeHTTP(w3, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w3.Code != http.StatusUnauthorized {
		t.Fatalf("期望 401，实际为 %d", w3.Code)
	}

	// 状态 3 已禁用
	u := model.User{Username: "d", Password: "x", Status: 3, Email: "d@example.com"}
	_ = db.DB.Create(&u).Error
	r4 := gin.New()
	r4.GET("/x",
		func(c *gin.Context) { c.Set("id", u.ID); c.Next() },
		UserStatusCheck(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)
	w4 := httptest.NewRecorder()
	r4.ServeHTTP(w4, httptest.NewRequest(http.MethodGet, "/x", nil))
	if w4.Code != http.StatusForbidden {
		t.Fatalf("期望 403，实际为 %d", w4.Code)
	}
}

// 测试内容：验证管理员校验对非管理员返回 403、管理员返回 200。
func TestAdminCheck(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	r.GET("/admin",
		func(c *gin.Context) { c.Set("admin", false); c.Next() },
		AdminCheck(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if w.Code != http.StatusForbidden {
		t.Fatalf("期望 403 for non-admin，实际为 %d", w.Code)
	}

	r2 := gin.New()
	r2.GET("/admin",
		func(c *gin.Context) { c.Set("admin", true); c.Next() },
		AdminCheck(),
		func(c *gin.Context) { c.Status(http.StatusOK) },
	)
	w2 := httptest.NewRecorder()
	r2.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/admin", nil))
	if w2.Code != http.StatusOK {
		t.Fatalf("期望 200 for admin，实际为 %d", w2.Code)
	}
}

// 测试内容：验证清除用户状态缓存会移除本地缓存条目。
func TestClearUserStatusCache_RemovesLocalCache(t *testing.T) {
	setupTestDB(t)
	resetStatusCache()

	statusCache.Store(uint(1), cachedStatus{Status: 2})
	ClearUserStatusCache(uint(1))
	if _, ok := statusCache.Load(uint(1)); ok {
		t.Fatalf("期望缓存条目被移除")
	}
}
