package admin

import (
	"net/http"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/service"
	"strconv"

	"github.com/gin-gonic/gin"
)

type ImageResponse struct {
	model.Image
	Username string `json:"username"`
}

// GetImageList 获取图片列表
func GetImageList(c *gin.Context) {
	pageStr := c.DefaultQuery("page", "1")
	pageSizeStr := c.DefaultQuery("page_size", "10")
	username := c.Query("username")
	id := c.Query("id")

	page, _ := strconv.Atoi(pageStr)
	pageSize, _ := strconv.Atoi(pageSizeStr)
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}

	images, total, page, pageSize, err := service.ListImagesForAdmin(service.AdminImageListParams{
		PaginationQuery: service.PaginationQuery{Page: page, PageSize: pageSize},
		Username:        username,
		ID:              id,
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取图片列表失败"})
		return
	}

	// 构造返回数据
	var response []ImageResponse
	for _, img := range images {
		response = append(response, ImageResponse{
			Image:    img,
			Username: img.User.Username,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"list":      response,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// DeleteImage 删除图片
func DeleteImage(c *gin.Context) {
	id := c.Param("id")

	image, err := service.GetImageByIDForAdmin(id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "图片不存在"})
		return
	}

	if err := service.DeleteImage(image); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "删除成功"})
}

// BatchDeleteImages 批量删除图片
func BatchDeleteImages(c *gin.Context) {
	var req struct {
		Ids []uint `json:"ids" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数格式错误"})
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

	images, err := service.GetImagesByIDsForAdmin(req.Ids)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "查找图片失败"})
		return
	}

	if len(images) == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "未找到图片"})
		return
	}

	if err := service.BatchDeleteImages(images); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "删除失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "删除成功", "deleted_count": len(images)})
}
