package admin

import (
	"fmt"
	"net/http"
	"perfect-pic-server/internal/service"
	"perfect-pic-server/internal/utils"

	"github.com/gin-gonic/gin"
)

type UpdateSettingRequest struct {
	Key   string `json:"key" binding:"required"`
	Value string `json:"value"`
}

func GetSettings(c *gin.Context) {
	settings, err := service.ListSettingsForAdmin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取配置失败"})
		return
	}

	c.JSON(http.StatusOK, settings)
}

func UpdateSettings(c *gin.Context) {
	var reqs []UpdateSettingRequest
	if err := c.ShouldBindJSON(&reqs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数格式错误"})
		return
	}

	items := make([]service.UpdateSettingPayload, 0, len(reqs))
	for _, item := range reqs {
		items = append(items, service.UpdateSettingPayload{Key: item.Key, Value: item.Value})
	}

	err := service.UpdateSettingsForAdmin(items)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "配置更新成功",
		"count":   len(reqs),
	})
}

func SendTestEmail(c *gin.Context) {
	var req struct {
		ToEmail string `json:"to_email" binding:"required,email"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "邮箱格式不正确"})
		return
	}

	if ok, msg := utils.ValidateEmail(req.ToEmail); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	if err := service.SendTestEmail(req.ToEmail); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("发送失败: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "测试邮件已发送"})
}
