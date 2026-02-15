package middleware

import "github.com/gin-gonic/gin"

// SecurityHeaders 添加安全相关的 HTTP 响应头
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// 防止浏览器猜测内容类型
		c.Header("X-Content-Type-Options", "nosniff")

		// 防止点击劫持 (Clickjacking)
		c.Header("X-Frame-Options", "DENY")

		// Content Security Policy (CSP)
		// 限制资源加载来源，防止 XSS
		// default-src 'self': 默认只允许加载同源资源
		// img-src: 允许同源、data:、blob: 以及验证码服务 (Geetest, Google, hCaptcha) 的图片
		// style-src: 允许同源、内联样式以及验证码服务的样式
		// script-src: 允许同源以及验证码服务 (Geetest, Cloudflare, Google, hCaptcha) 的脚本
		// connect-src: 允许连接到验证码服务的 API
		// frame-src: 允许嵌入验证码服务的 iframe
		// frame-ancestors 'none': 禁止被其他网站嵌入 (替代 X-Frame-Options)
		csp := "default-src 'self'; " +
			"img-src 'self' data: blob: https://*.geetest.com https://www.google.com https://www.gstatic.com https://*.hcaptcha.com https://hcaptcha.com; " +
			"style-src 'self' 'unsafe-inline' https://*.geetest.com https://*.hcaptcha.com https://hcaptcha.com; " +
			"script-src 'self' https://*.geetest.com https://challenges.cloudflare.com https://www.google.com https://www.gstatic.com https://*.hcaptcha.com https://hcaptcha.com; " +
			"connect-src 'self' https://*.geetest.com https://challenges.cloudflare.com https://www.google.com https://*.hcaptcha.com https://hcaptcha.com; " +
			"object-src 'none'; " +
			"frame-src 'self' https://*.geetest.com https://challenges.cloudflare.com https://www.google.com https://*.hcaptcha.com https://hcaptcha.com; " +
			"base-uri 'self'; " +
			"frame-ancestors 'none';"

		c.Header("Content-Security-Policy", csp)

		c.Next()
	}
}
