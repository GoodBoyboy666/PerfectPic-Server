package admin

import (
	"net/http"
	"perfect-pic-server/internal/service"

	"github.com/gin-gonic/gin"
)

// GetServerStats 获取服务器概览统计信息
func GetServerStats(c *gin.Context) {
	stats, err := service.GetServerStatsForAdmin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "统计图片数据失败"})
		return
	}

	c.JSON(http.StatusOK, stats)
}
