package handler

import (
	"net/http"
	"perfect-pic-server/internal/config"
	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/service"

	"github.com/gin-gonic/gin"
)

func GetWebInfo(c *gin.Context) {
	// 只获取前台展示用的公共配置项
	allowKeys := []string{
		consts.ConfigSiteName,
		consts.ConfigSiteDescription,
		consts.ConfigSiteLogo,
		consts.ConfigSiteFavicon,
	}

	type WebInfoItem struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	}

	var response []WebInfoItem
	for _, key := range allowKeys {
		val := service.GetString(key)
		response = append(response, WebInfoItem{
			Key:   key,
			Value: val,
		})
	}
	c.JSON(http.StatusOK, response)
}

func GetImagePrefix(c *gin.Context) {
	cfg := config.Get()
	c.JSON(http.StatusOK, gin.H{
		"image_prefix": cfg.Upload.URLPrefix,
	})
}

func GetAvatarPrefix(c *gin.Context) {
	cfg := config.Get()
	c.JSON(http.StatusOK, gin.H{
		"avatar_prefix": cfg.Upload.AvatarURLPrefix,
	})
}

func GetDefaultStorageQuota(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"default_storage_quota": service.GetSystemDefaultStorageQuota(),
	})
}
