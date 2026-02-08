package handler

import (
	"log"
	"net/http"
	"perfect-pic-server/internal/service"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

func UploadImage(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请选择文件"})
		return
	}

	// 从 JWT 中间件获取用户ID
	userID, exists := c.Get("id")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "未获取到用户信息"})
		return
	}
	uid, ok := userID.(uint)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的用户ID类型"})
		return
	}

	imageRecord, url, err := service.ProcessImageUpload(file, uid)
	if err != nil {
		errStr := err.Error()
		if strings.Contains(errStr, "存储空间不足") {
			c.JSON(http.StatusForbidden, gin.H{"error": errStr})
		} else if strings.Contains(errStr, "不支持的文件类型") || strings.Contains(errStr, "文件大小") {
			c.JSON(http.StatusBadRequest, gin.H{"error": errStr})
		} else {
			// 对于其他错误（包括系统错误），记录日志并返回通用错误信息
			log.Printf("Upload failed: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "上传失败，请稍后重试"})
		}
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"msg": "上传成功",
		"url": url,
		"id":  imageRecord.ID,
	})
}

func GetMyImages(c *gin.Context) {
	userID, _ := c.Get("id")

	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("page_size", "10")
	filename := c.Query("filename")
	id := c.Query("id")

	page, _ := strconv.Atoi(pageStr)
	pageSize, _ := strconv.Atoi(pageSizeStr)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}

	uid, ok := userID.(uint)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的用户ID类型"})
		return
	}

	images, total, page, pageSize, err := service.ListUserImages(service.UserImageListParams{
		PaginationQuery: service.PaginationQuery{Page: page, PageSize: pageSize},
		UserID:          uid,
		Filename:        filename,
		ID:              id,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取图片列表失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"list":      images,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// DeleteMyImage 用户删除自己的图片
func DeleteMyImage(c *gin.Context) {
	userID, _ := c.Get("id")
	id := c.Param("id")
	uid, ok := userID.(uint)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的用户ID类型"})
		return
	}

	image, err := service.GetUserOwnedImage(id, uid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "图片不存在或无权删除"})
		return
	}

	if err := service.DeleteImage(image); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

// BatchDeleteMyImages 批量删除用户自己的图片
func BatchDeleteMyImages(c *gin.Context) {
	userID, _ := c.Get("id")
	uid, ok := userID.(uint)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "无效的用户ID类型"})
		return
	}

	var req struct {
		Ids []uint `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	if len(req.Ids) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "请选择要删除的图片"})
		return
	}

	if len(req.Ids) > 50 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "一次最多只能删除 50 张图片"})
		return
	}

	images, err := service.GetImagesByIDsForUser(req.Ids, uid)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查找图片失败"})
		return
	}

	if len(images) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "未找到指定图片或无权删除"})
		return
	}

	if err := service.BatchDeleteImages(images); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "删除成功", "deleted_count": len(images)})
}
