package admin

import (
	"fmt"
	"log"
	"net/http"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/service"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type UpdateSettingRequest struct {
	Key   string `json:"key" binding:"required"`
	Value string `json:"value" binding:"required"`
}

func GetSettings(c *gin.Context) {
	var dbSettings []model.Setting
	if err := db.DB.Find(&dbSettings).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "获取配置失败"})
		return
	}

	c.JSON(http.StatusOK, dbSettings)
}

func UpdateSettings(c *gin.Context) {
	var reqs []UpdateSettingRequest
	if err := c.ShouldBindJSON(&reqs); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数格式错误"})
		return
	}

	// 开启事务 (Transaction)
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		for _, item := range reqs {
			setting := model.Setting{
				Key:   item.Key,
				Value: item.Value,
			}

			// 尝试更新 Value 字段
			// 使用 Model(&setting) 会利用主键 Key 进行条件匹配
			result := tx.Model(&setting).Select("Value").Updates(setting)
			if result.Error != nil {
				return result.Error
			}

			// 如果没有记录被更新（说明不存在），则创建新记录
			if result.RowsAffected == 0 {
				if err := tx.Create(&setting).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})

	if err != nil {
		log.Printf("配置更新失败: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "更新失败"})
		return
	}

	// 清空内存缓存
	service.ClearCache()

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

	if err := service.SendTestEmail(req.ToEmail); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("发送失败: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "测试邮件已发送"})
}
