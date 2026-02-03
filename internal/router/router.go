package router

import (
	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/handler"
	"perfect-pic-server/internal/handler/admin"
	"perfect-pic-server/internal/middleware"

	"github.com/gin-gonic/gin"
)

func InitRouter(r *gin.Engine) {
	// 注册全局安全标头中间件
	r.Use(middleware.SecurityHeaders())

	api := r.Group("/api")
	{
		// 应用请求体大小限制中间件
		api.Use(middleware.BodyLimitMiddleware())

		// 公开路由
		api.GET("/ping", func(c *gin.Context) {
			c.JSON(200, gin.H{"message": "pong from gin"})
		})
		api.GET("/init", handler.GetInitState)

		// 认证限流：读取配置
		authLimiter := middleware.RateLimitMiddleware(consts.ConfigRateLimitAuthRPS, consts.ConfigRateLimitAuthBurst)
		api.POST("/init", authLimiter, handler.Init)
		api.POST("/login", authLimiter, handler.Login)
		api.POST("/register", authLimiter, handler.Register)

		api.GET("/auth/email-verify", handler.EmailVerify)
		api.GET("/auth/email-change-verify", handler.EmailChangeVerify)

		api.POST("/auth/password/reset/request", handler.RequestPasswordReset)
		api.POST("/auth/password/reset", handler.ResetPassword)

		api.GET("/register", handler.GetRegisterState)
		api.GET("/captcha", handler.GetCaptcha)
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
			userGroup.POST("/email", handler.RequestUpdateEmail)

			// 上传限流：读取配置
			uploadLimiter := middleware.RateLimitMiddleware(consts.ConfigRateLimitUploadRPS, consts.ConfigRateLimitUploadBurst)
			userGroup.PATCH("/avatar", uploadLimiter, handler.UpdateSelfAvatar)

			// Image Upload
			userGroup.POST("/upload", uploadLimiter, handler.UploadImage)
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
