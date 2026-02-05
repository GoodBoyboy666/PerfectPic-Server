package middleware

import (
	"fmt"
	"net/http"
	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/service"
	"strings"

	"github.com/gin-gonic/gin"
)

// BodyLimitMiddleware 限制请求体大小
func BodyLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 跳过上传相关的路由
		// 这里简单通过路径判断
		path := c.Request.URL.Path
		if strings.HasSuffix(path, "/upload") || strings.HasSuffix(path, "/avatar") {
			c.Next()
			return
		}

		maxSizeMB := service.GetInt(consts.ConfigMaxRequestBodySize)
		if maxSizeMB <= 0 {
			// 如果未设置或为0，默认 2MB
			maxSizeMB = 2
		}

		// 限制大小 (MB -> Bytes)
		maxBytes := int64(maxSizeMB) * 1024 * 1024

		// 使用 MaxBytesReader 限制读取的字节数
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)

		c.Next()
	}
}

// UploadBodyLimitMiddleware 限制上传/头像接口的请求体大小
func UploadBodyLimitMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		maxSizeMB := service.GetInt(consts.ConfigMaxUploadSize)
		if maxSizeMB <= 0 {
			maxSizeMB = 10
		}
		maxBytes := int64(maxSizeMB) * 1024 * 1024

		if c.Request.ContentLength > maxBytes && c.Request.ContentLength != -1 {
			c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": fmt.Sprintf("文件大小不能超过 %dMB", maxSizeMB)})
			c.Abort()
			return
		}

		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxBytes)
		c.Next()
	}
}
