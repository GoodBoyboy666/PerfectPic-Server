package consts

const (

	// ConfigSiteName 网站名称
	ConfigSiteName = "site_name"

	// ConfigSiteDescription 网站描述
	ConfigSiteDescription = "site_description"

	// ConfigSiteLogo 网站Logo URL
	ConfigSiteLogo = "site_logo"

	// ConfigSiteFavicon 网站Favicon URL
	ConfigSiteFavicon = "site_favicon"

	// ConfigBaseURL 网站基础URL (例如 http://localhost:8080)
	ConfigBaseURL = "base_url"

	// ConfigAllowInit 是否允许初始化管理员账号 (true/false)
	ConfigAllowInit = "allow_init"

	// ConfigAllowRegister 是否开放注册 (true/false)
	ConfigAllowRegister = "allow_register"

	// ConfigEnableSMTP 是否启用SMTP发送邮件 (true/false)
	ConfigEnableSMTP = "enable_smtp"

	// ConfigBlockUnverifiedUsers 是否阻止未验证邮箱用户登录 (true/false)
	ConfigBlockUnverifiedUsers = "block_unverified_users"

	// ConfigRequireEmailVerification 注册是否强制要求验证邮箱 (true/false)
	ConfigRequireEmailVerification = "require_email_verification"

	// ConfigMaxUploadSize 图片最大上传限制 (MB)
	ConfigMaxUploadSize = "max_upload_size"

	// ConfigAllowFileExtensions 允许上传的文件扩展名 (逗号分隔)
	ConfigAllowFileExtensions = "allow_file_extensions"

	// ConfigDefaultStorageQuota 默认存储配额 (字节)
	ConfigDefaultStorageQuota = "default_storage_quota"

	// ConfigRateLimitEnabled 是否开启限流
	ConfigRateLimitEnabled = "rate_limit_enabled"

	// ConfigRateLimitAuthRPS 认证接口限流 RPS
	ConfigRateLimitAuthRPS = "rate_limit_auth_rps"

	// ConfigRateLimitAuthBurst 认证接口限流 Burst
	ConfigRateLimitAuthBurst = "rate_limit_auth_burst"

	// ConfigRateLimitUploadRPS 上传接口限流 RPS
	ConfigRateLimitUploadRPS = "rate_limit_upload_rps"

	// ConfigRateLimitUploadBurst 上传接口限流 Burst
	ConfigRateLimitUploadBurst = "rate_limit_upload_burst"

	// ConfigEnableSensitiveRateLimit 是否开启敏感操作（忘记密码、修改邮箱）频率限制
	ConfigEnableSensitiveRateLimit = "enable_sensitive_rate_limit"

	// ConfigMaxRequestBodySize 最大API请求体大小 (MB, 排除文件上传)
	ConfigMaxRequestBodySize = "max_request_body_size"

	// ConfigStaticCacheControl 静态资源缓存设置 (Cache-Control header value)
	ConfigStaticCacheControl = "static_cache_control"
)
