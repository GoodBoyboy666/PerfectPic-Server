package router

import (
	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/handler"
	"perfect-pic-server/internal/handler/admin"
	"perfect-pic-server/internal/middleware"
	"time"

	"github.com/gin-gonic/gin"
)

func InitRouter(r *gin.Engine) {
	// 注册全局安全标头中间件
	r.Use(middleware.SecurityHeaders())

	api := r.Group("/api")
	{
		// 应用请求体大小限制中间件
		api.Use(middleware.BodyLimitMiddleware())

		// 认证限流：读取配置
		authLimiter := middleware.RateLimitMiddleware(consts.ConfigRateLimitAuthRPS, consts.ConfigRateLimitAuthBurst)

		// 公开路由
		api.GET("/ping", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "pong from gin"})
		})
		api.GET("/init", handler.GetInitState)

		api.POST("/init", authLimiter, handler.Init)
		api.POST("/login", authLimiter, handler.Login)
		api.POST("/register", authLimiter, handler.Register)

		api.POST("/auth/email-verify", handler.EmailVerify)
		api.POST("/auth/email-change-verify", handler.EmailChangeVerify)

		// 限制重置密码请求频率为每2分钟1次
		resetLimiter := middleware.IntervalRateMiddleware(2 * time.Minute)
		api.POST("/auth/password/reset/request", resetLimiter, handler.RequestPasswordReset)
		api.POST("/auth/password/reset", handler.ResetPassword)

		api.GET("/register", handler.GetRegisterState)
		api.GET("/captcha", authLimiter, handler.GetCaptcha)
		api.GET("/webinfo", handler.GetWebInfo)
		api.GET("/image_prefix", handler.GetImagePrefix)
		api.GET("/avatar_prefix", handler.GetAvatarPrefix)

		// 权限路由
		userGroup := api.Group("/user")
		userGroup.Use(middleware.JWTAuth())         // 挂载鉴权中间件
		userGroup.Use(middleware.UserStatusCheck()) // 挂载状态检查中间件
		{
			userGroup.GET("/profile", handler.GetSelfInfo)
			userGroup.PATCH("/username", handler.UpdateSelfUsername)
			userGroup.PATCH("/password", handler.UpdateSelfPassword)

			// 限制修改邮箱请求频率为每2分钟1次
			emailLimiter := middleware.IntervalRateMiddleware(2 * time.Minute)
			userGroup.POST("/email", emailLimiter, handler.RequestUpdateEmail)

			// 上传限流：读取配置
			uploadLimiter := middleware.RateLimitMiddleware(consts.ConfigRateLimitUploadRPS, consts.ConfigRateLimitUploadBurst)
			uploadBodyLimit := middleware.UploadBodyLimitMiddleware()
			userGroup.PATCH("/avatar", uploadBodyLimit, uploadLimiter, handler.UpdateSelfAvatar)

			// Image Upload
			userGroup.POST("/upload", uploadBodyLimit, uploadLimiter, handler.UploadImage)
			userGroup.GET("/images", handler.GetMyImages)
			userGroup.DELETE("/images/batch", handler.BatchDeleteMyImages)
			userGroup.DELETE("/images/:id", handler.DeleteMyImage)
			userGroup.GET("/images/count", handler.GetSelfImagesCount)

			userGroup.GET("/ping", func(c *gin.Context) {
				c.JSON(200, gin.H{"message": "pong with auth"})
			})
		}

		// Admin 路由
		adminGroup := api.Group("/admin")
		adminGroup.Use(middleware.JWTAuth())
		adminGroup.Use(middleware.UserStatusCheck()) // 挂载状态检查中间件
		adminGroup.Use(middleware.AdminCheck())
		{
			adminGroup.GET("/stats", admin.GetServerStats)

			adminGroup.GET("/settings", admin.GetSettings)
			adminGroup.PATCH("/settings", admin.UpdateSettings)
			adminGroup.POST("/email/test", admin.SendTestEmail)

			// 用户管理
			adminGroup.GET("/users", admin.GetUserList)
			adminGroup.GET("/users/:id", admin.GetUserDetail)
			adminGroup.POST("/users", admin.CreateUser)
			adminGroup.PATCH("/users/:id", admin.UpdateUser)
			adminGroup.POST("/users/:id/avatar", admin.UpdateUserAvatar)
			adminGroup.DELETE("/users/:id/avatar", admin.RemoveUserAvatar)
			adminGroup.DELETE("/users/:id", admin.DeleteUser)

			// 图片管理
			adminGroup.GET("/images", admin.GetImageList)
			adminGroup.DELETE("/images/batch", admin.BatchDeleteImages)
			adminGroup.DELETE("/images/:id", admin.DeleteImage)
		}
	}
}
