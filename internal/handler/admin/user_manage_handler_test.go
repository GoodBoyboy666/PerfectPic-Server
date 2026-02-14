package admin

import (
	"bytes"
	"encoding/json"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/testutils"

	"github.com/gin-gonic/gin"
)

// 测试内容：验证管理员用户增删改查及头像操作的完整流程。
func TestUserManageHandlers_CRUD(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	// 为列表/更新/删除测试预置一个用户。
	u := model.User{Username: "seed", Password: "x", Status: 1, Email: "seed@example.com"}
	_ = db.DB.Create(&u).Error

	r := gin.New()
	r.GET("/users", GetUserList)
	r.GET("/users/:id", GetUserDetail)
	r.POST("/users", CreateUser)
	r.PATCH("/users/:id", UpdateUser)
	r.DELETE("/users/:id", DeleteUser)
	r.POST("/users/:id/avatar", UpdateUserAvatar)
	r.DELETE("/users/:id/avatar", RemoveUserAvatar)

	// 列表
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/users?page=1&page_size=10", nil))
	if w1.Code != http.StatusOK {
		t.Fatalf("list 期望 200，实际为 %d body=%s", w1.Code, w1.Body.String())
	}

	// 详情
	w1b := httptest.NewRecorder()
	r.ServeHTTP(w1b, httptest.NewRequest(http.MethodGet, "/users/1", nil))
	if w1b.Code != http.StatusOK {
		t.Fatalf("detail 期望 200，实际为 %d body=%s", w1b.Code, w1b.Body.String())
	}

	// 创建
	bodyCreate, _ := json.Marshal(gin.H{"username": "alice_1", "password": "abc12345", "email": "a1@example.com"})
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader(bodyCreate)))
	if w2.Code != http.StatusCreated {
		t.Fatalf("create 期望 201，实际为 %d body=%s", w2.Code, w2.Body.String())
	}

	// 更新
	bodyUpdate, _ := json.Marshal(gin.H{"status": 2})
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, httptest.NewRequest(http.MethodPatch, "/users/1", bytes.NewReader(bodyUpdate)))
	if w3.Code != http.StatusOK {
		t.Fatalf("update 期望 200，实际为 %d body=%s", w3.Code, w3.Body.String())
	}

	// 更新头像
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	part, _ := mw.CreateFormFile("file", "a.png")
	_, _ = part.Write(testutils.MinimalPNG())
	_ = mw.Close()
	reqAvatar := httptest.NewRequest(http.MethodPost, "/users/1/avatar", &mp)
	reqAvatar.Header.Set("Content-Type", mw.FormDataContentType())
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, reqAvatar)
	if w4.Code != http.StatusOK {
		t.Fatalf("update avatar 期望 200，实际为 %d body=%s", w4.Code, w4.Body.String())
	}

	// 移除头像
	w5 := httptest.NewRecorder()
	r.ServeHTTP(w5, httptest.NewRequest(http.MethodDelete, "/users/1/avatar", nil))
	if w5.Code != http.StatusOK {
		t.Fatalf("remove avatar 期望 200，实际为 %d body=%s", w5.Code, w5.Body.String())
	}

	// 删除（软删除）
	w6 := httptest.NewRecorder()
	r.ServeHTTP(w6, httptest.NewRequest(http.MethodDelete, "/users/1?hard_delete=false", nil))
	if w6.Code != http.StatusOK {
		t.Fatalf("delete 期望 200，实际为 %d body=%s", w6.Code, w6.Body.String())
	}
}

// 测试内容：验证管理员用户接口的参数错误与未找到等分支。
func TestUserManageHandlers_ErrorBranches(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	r := gin.New()
	r.GET("/users/:id", GetUserDetail)
	r.POST("/users", CreateUser)
	r.PATCH("/users/:id", UpdateUser)
	r.DELETE("/users/:id", DeleteUser)
	r.POST("/users/:id/avatar", UpdateUserAvatar)
	r.DELETE("/users/:id/avatar", RemoveUserAvatar)

	// 无效 id
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/users/not-int", nil))
	if w1.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d", w1.Code)
	}

	// 未找到
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/users/999", nil))
	if w2.Code != http.StatusNotFound {
		t.Fatalf("期望 404，实际为 %d", w2.Code)
	}

	// 创建绑定错误
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader([]byte("{bad"))))
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d", w3.Code)
	}

	// 更新时 id 无效
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, httptest.NewRequest(http.MethodPatch, "/users/not-int", bytes.NewReader([]byte(`{}`))))
	if w4.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d", w4.Code)
	}

	// 更新时状态校验错误
	w5 := httptest.NewRecorder()
	r.ServeHTTP(w5, httptest.NewRequest(http.MethodPatch, "/users/1", bytes.NewReader([]byte(`{"status":9}`))))
	if w5.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d body=%s", w5.Code, w5.Body.String())
	}

	// 删除时 id 无效
	w6 := httptest.NewRecorder()
	r.ServeHTTP(w6, httptest.NewRequest(http.MethodDelete, "/users/not-int", nil))
	if w6.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d", w6.Code)
	}

	// 头像缺少文件
	w7 := httptest.NewRecorder()
	r.ServeHTTP(w7, httptest.NewRequest(http.MethodPost, "/users/1/avatar", nil))
	if w7.Code != http.StatusBadRequest {
		t.Fatalf("期望 400，实际为 %d", w7.Code)
	}

	// 删除头像未找到
	w8 := httptest.NewRecorder()
	r.ServeHTTP(w8, httptest.NewRequest(http.MethodDelete, "/users/999/avatar", nil))
	if w8.Code != http.StatusNotFound {
		t.Fatalf("期望 404，实际为 %d", w8.Code)
	}
}
