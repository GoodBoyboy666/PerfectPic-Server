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

func TestUserManageHandlers_CRUD(t *testing.T) {
	gin.SetMode(gin.TestMode)
	setupTestDB(t)

	tmp := t.TempDir()
	oldwd, _ := os.Getwd()
	_ = os.Chdir(tmp)
	defer func() { _ = os.Chdir(oldwd) }()

	// Seed one user for list/update/delete tests.
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

	// List
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/users?page=1&page_size=10", nil))
	if w1.Code != http.StatusOK {
		t.Fatalf("list expected 200, got %d body=%s", w1.Code, w1.Body.String())
	}

	// Detail
	w1b := httptest.NewRecorder()
	r.ServeHTTP(w1b, httptest.NewRequest(http.MethodGet, "/users/1", nil))
	if w1b.Code != http.StatusOK {
		t.Fatalf("detail expected 200, got %d body=%s", w1b.Code, w1b.Body.String())
	}

	// Create
	bodyCreate, _ := json.Marshal(gin.H{"username": "alice_1", "password": "abc12345", "email": "a1@example.com"})
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader(bodyCreate)))
	if w2.Code != http.StatusCreated {
		t.Fatalf("create expected 201, got %d body=%s", w2.Code, w2.Body.String())
	}

	// Update
	bodyUpdate, _ := json.Marshal(gin.H{"status": 2})
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, httptest.NewRequest(http.MethodPatch, "/users/1", bytes.NewReader(bodyUpdate)))
	if w3.Code != http.StatusOK {
		t.Fatalf("update expected 200, got %d body=%s", w3.Code, w3.Body.String())
	}

	// Update avatar
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
		t.Fatalf("update avatar expected 200, got %d body=%s", w4.Code, w4.Body.String())
	}

	// Remove avatar
	w5 := httptest.NewRecorder()
	r.ServeHTTP(w5, httptest.NewRequest(http.MethodDelete, "/users/1/avatar", nil))
	if w5.Code != http.StatusOK {
		t.Fatalf("remove avatar expected 200, got %d body=%s", w5.Code, w5.Body.String())
	}

	// Delete (soft delete)
	w6 := httptest.NewRecorder()
	r.ServeHTTP(w6, httptest.NewRequest(http.MethodDelete, "/users/1?hard_delete=false", nil))
	if w6.Code != http.StatusOK {
		t.Fatalf("delete expected 200, got %d body=%s", w6.Code, w6.Body.String())
	}
}

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

	// bad id
	w1 := httptest.NewRecorder()
	r.ServeHTTP(w1, httptest.NewRequest(http.MethodGet, "/users/not-int", nil))
	if w1.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w1.Code)
	}

	// not found
	w2 := httptest.NewRecorder()
	r.ServeHTTP(w2, httptest.NewRequest(http.MethodGet, "/users/999", nil))
	if w2.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w2.Code)
	}

	// create bind error
	w3 := httptest.NewRecorder()
	r.ServeHTTP(w3, httptest.NewRequest(http.MethodPost, "/users", bytes.NewReader([]byte("{bad"))))
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w3.Code)
	}

	// update invalid id
	w4 := httptest.NewRecorder()
	r.ServeHTTP(w4, httptest.NewRequest(http.MethodPatch, "/users/not-int", bytes.NewReader([]byte(`{}`))))
	if w4.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w4.Code)
	}

	// update invalid status validation error
	w5 := httptest.NewRecorder()
	r.ServeHTTP(w5, httptest.NewRequest(http.MethodPatch, "/users/1", bytes.NewReader([]byte(`{"status":9}`))))
	if w5.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d body=%s", w5.Code, w5.Body.String())
	}

	// delete invalid id
	w6 := httptest.NewRecorder()
	r.ServeHTTP(w6, httptest.NewRequest(http.MethodDelete, "/users/not-int", nil))
	if w6.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w6.Code)
	}

	// avatar missing file
	w7 := httptest.NewRecorder()
	r.ServeHTTP(w7, httptest.NewRequest(http.MethodPost, "/users/1/avatar", nil))
	if w7.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w7.Code)
	}

	// remove avatar not found
	w8 := httptest.NewRecorder()
	r.ServeHTTP(w8, httptest.NewRequest(http.MethodDelete, "/users/999/avatar", nil))
	if w8.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w8.Code)
	}
}
