package handler

import (
	"log"
	"net/http"
	"perfect-pic-server/internal/config"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/service"
	"perfect-pic-server/internal/utils"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

// GetSelfInfo 获取当前用户信息
func GetSelfInfo(c *gin.Context) {
	userId, exists := c.Get("id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "获取用户ID失败"})
		return
	}

	var user model.User
	if err := db.DB.First(&user, userId).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	// 计算实际配额
	quota := service.GetUserStorageQuota(&user)

	c.JSON(http.StatusOK, gin.H{
		"id":            user.ID,
		"username":      user.Username,
		"avatar":        user.Avatar,
		"admin":         user.Admin,
		"storage_quota": quota,
		"storage_used":  user.StorageUsed,
	})
}

// UpdateSelfUsername 修改自己的用户名
func UpdateSelfUsername(c *gin.Context) {
	userId, exists := c.Get("id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "获取用户ID失败"})
		return
	}

	var req struct {
		Username string `json:"username" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	if ok, msg := utils.ValidateUsername(req.Username); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	// 检查用户名是否已存在
	var count int64
	db.DB.Model(&model.User{}).Where("username = ? AND id != ?", req.Username, userId).Count(&count)
	if count > 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "用户名已存在"})
		return
	}

	if err := db.DB.Model(&model.User{}).Where("id = ?", userId).Update("username", req.Username).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}

	// 获取配置
	cfg := config.Get()
	// 获取管理员权限状态
	adminVal, _ := c.Get("admin")
	isAdmin := false
	if val, ok := adminVal.(bool); ok {
		isAdmin = val
	}

	uid, ok := userId.(uint)
	if !ok {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "用户ID类型错误"})
		return
	}

	// 签发新 Token
	token, _ := utils.GenerateLoginToken(uid, req.Username, isAdmin, time.Hour*time.Duration(cfg.JWT.ExpirationHours))

	c.JSON(http.StatusOK, gin.H{
		"message": "用户名更新成功",
		"token":   token,
	})
}

// UpdateSelfPassword 修改自己的密码
func UpdateSelfPassword(c *gin.Context) {
	userId, exists := c.Get("id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "获取用户ID失败"})
		return
	}

	var req struct {
		OldPassword string `json:"old_password" binding:"required"`
		NewPassword string `json:"new_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	if ok, msg := utils.ValidatePassword(req.NewPassword); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	var user model.User
	if err := db.DB.First(&user, userId).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	// 验证旧密码
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.OldPassword)); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "旧密码错误"})
		return
	}

	// 加密新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码加密失败"})
		return
	}

	if err := db.DB.Model(&user).Update("password", string(hashedPassword)).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "密码更新成功"})
}

// UpdateSelfAvatar 修改自己的头像
func UpdateSelfAvatar(c *gin.Context) {
	userId, exists := c.Get("id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "获取用户ID失败"})
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
	var user model.User
	if err := db.DB.First(&user, userId).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	newFilename, err := service.UpdateUserAvatar(&user, file)
	if err != nil {
		log.Printf("UpdateUserAvatar error: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "头像更新失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "头像更新成功", "avatar": newFilename})
}

func GetSelfImagesCount(c *gin.Context) {
	userId, exists := c.Get("id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "获取用户ID失败"})
		return
	}

	var count int64
	if err := db.DB.Model(&model.Image{}).Where("user_id = ?", userId).Count(&count).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取图片数量失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"image_count": count,
	})
}
