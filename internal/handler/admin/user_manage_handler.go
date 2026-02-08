package admin

import (
	"log"
	"net/http"
	"perfect-pic-server/internal/middleware"
	"perfect-pic-server/internal/service"
	"strconv"

	"github.com/gin-gonic/gin"
)

// GetUserList 获取用户列表
func GetUserList(c *gin.Context) {
	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("page_size", "10")
	keyword := c.Query("keyword")
	showDeleted := c.DefaultQuery("show_deleted", "false")
	order := c.Query("order")

	page, _ := strconv.Atoi(pageStr)
	pageSize, _ := strconv.Atoi(pageSizeStr)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}

	users, total, err := service.ListUsersForAdmin(service.AdminUserListParams{
		Page:        page,
		PageSize:    pageSize,
		Keyword:     keyword,
		ShowDeleted: showDeleted == "true",
		Order:       order,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取用户列表失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":      users,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// GetUserDetail 获取指定用户信息
func GetUserDetail(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的用户ID"})
		return
	}

	user, err := service.GetUserDetailForAdmin(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"data": user})
}

// CreateUserRequest 创建用户请求结构体
type CreateUserRequest struct {
	Username      string  `json:"username" binding:"required"`
	Password      string  `json:"password" binding:"required"`
	Email         *string `json:"email"`
	EmailVerified *bool   `json:"email_verified"`
	StorageQuota  *int64  `json:"storage_quota"`
	Status        *int    `json:"status"`
}

// CreateUser 创建用户
func CreateUser(c *gin.Context) {
	var req CreateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数格式错误"})
		return
	}

	user, validateMsg, err := service.CreateUserForAdmin(service.AdminCreateUserInput{
		Username:      req.Username,
		Password:      req.Password,
		Email:         req.Email,
		EmailVerified: req.EmailVerified,
		StorageQuota:  req.StorageQuota,
		Status:        req.Status,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "创建用户失败"})
		return
	}
	if validateMsg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": validateMsg})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "创建成功", "data": user})
}

// UpdateUserRequest 修改用户信息结构体
type UpdateUserRequest struct {
	Username      *string `json:"username"`
	Password      *string `json:"password"`
	Email         *string `json:"email"`
	EmailVerified *bool   `json:"email_verified"`
	StorageQuota  *int64  `json:"storage_quota"`
	Status        *int    `json:"status"`
}

// UpdateUser 修改用户信息
func UpdateUser(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的用户ID"})
		return
	}

	var req UpdateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	updates, errMsg, err := service.PrepareUserUpdatesForAdmin(uint(id), service.AdminUserUpdateInput{
		Username:      req.Username,
		Password:      req.Password,
		Email:         req.Email,
		EmailVerified: req.EmailVerified,
		StorageQuota:  req.StorageQuota,
		Status:        req.Status,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新用户失败"})
		return
	}
	if errMsg != "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": errMsg})
		return
	}

	if len(updates) > 0 {
		if err := service.ApplyUserUpdatesForAdmin(uint(id), updates); err != nil {
			if service.IsRecordNotFound(err) {
				c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "更新用户失败"})
			return
		}
		// 清除用户状态缓存
		middleware.ClearUserStatusCache(uint(id))
	}

	c.JSON(http.StatusOK, gin.H{"message": "更新成功"})
}

// UpdateUserAvatar 更新用户头像
func UpdateUserAvatar(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的用户ID"})
		return
	}

	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请选择文件"})
		return
	}

	valid, ext, err := service.ValidateImageFile(file)
	if !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	_ = ext

	user, err := service.GetUserDetailForAdmin(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	newFilename, err := service.UpdateUserAvatar(user, file)
	if err != nil {
		log.Printf("Admin UpdateUserAvatar error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "头像更新失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "头像更新成功", "avatar": newFilename})
}

// RemoveUserAvatar 移除用户头像
func RemoveUserAvatar(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的用户ID"})
		return
	}

	user, err := service.GetUserDetailForAdmin(uint(id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	if err := service.RemoveUserAvatar(user); err != nil {
		log.Printf("Admin RemoveUserAvatar error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "头像移除失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "头像已移除"})
}

// DeleteUser 删除用户
func DeleteUser(c *gin.Context) {
	idStr := c.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的用户ID"})
		return
	}

	hardDelete := c.DefaultQuery("hard_delete", "false")

	if err := service.DeleteUserForAdmin(uint(id), hardDelete == "true"); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除用户失败"})
		return
	}

	// 清除用户状态缓存
	middleware.ClearUserStatusCache(uint(id))

	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}
