package service

import (
	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"strconv"
	"sync"
)

var (
	// 内存缓存
	settingsCache sync.Map
)

const DefaultValueNotFound = "||__NOT_FOUND__||"

var DefaultSettings = []model.Setting{
	{Key: consts.ConfigSiteName, Value: "Perfect Pic", Desc: "网站名称", Category: "常规"},
	{Key: consts.ConfigSiteDescription, Value: "记录与分享完美瞬间", Desc: "网站描述", Category: "常规"},
	{Key: consts.ConfigSiteLogo, Value: "", Desc: "网站Logo URL", Category: "常规"},
	{Key: consts.ConfigSiteFavicon, Value: "", Desc: "网站Favicon URL", Category: "常规"},
	{Key: consts.ConfigBaseURL, Value: "http://localhost", Desc: "网站基础URL (用于生成链接)", Category: "常规"},
	{Key: consts.ConfigAllowInit, Value: "true", Desc: "是否允许初始化管理员账号", Category: "安全"},
	{Key: consts.ConfigAllowRegister, Value: "true", Desc: "是否开放注册", Category: "安全"},
	{Key: consts.ConfigEnableSMTP, Value: "false", Desc: "是否启用 SMTP 发送邮件", Category: "邮件服务"},
	{Key: consts.ConfigBlockUnverifiedUsers, Value: "false", Desc: "是否阻止未验证邮箱用户登录", Category: "安全"},
	{Key: consts.ConfigRequireEmailVerification, Value: "false", Desc: "是否强制要求注册验证邮箱", Category: "安全"},
	{Key: consts.ConfigMaxUploadSize, Value: "10", Desc: "单个文件最大大小 (MB)", Category: "上传"},
	{Key: consts.ConfigAllowFileExtensions, Value: ".jpg,.jpeg,.png,.gif,.webp", Desc: "允许上传的文件扩展名", Category: "上传"},
	{Key: consts.ConfigDefaultStorageQuota, Value: "1073741824", Desc: "默认用户存储配额 (Bytes, 默认为1GB)", Category: "上传"},
	{Key: consts.ConfigRateLimitEnabled, Value: "true", Desc: "是否开启接口限流", Category: "速率限制"},
	{Key: consts.ConfigRateLimitAuthRPS, Value: "0.5", Desc: "认证接口每秒请求限制 (RPS)", Category: "速率限制"},
	{Key: consts.ConfigRateLimitAuthBurst, Value: "2", Desc: "认证接口突发请求限制", Category: "速率限制"},
	{Key: consts.ConfigRateLimitUploadRPS, Value: "1.0", Desc: "上传接口每秒请求限制 (RPS)", Category: "速率限制"},
	{Key: consts.ConfigRateLimitUploadBurst, Value: "5", Desc: "上传接口突发请求限制", Category: "速率限制"},
	{Key: consts.ConfigEnableSensitiveRateLimit, Value: "true", Desc: "是否开启敏感操作（忘记密码、修改邮箱）频率限制", Category: "速率限制"},
	{Key: consts.ConfigMaxRequestBodySize, Value: "2", Desc: "非文件上传接口最大请求体限制 (MB)", Category: "服务"},
	{Key: consts.ConfigStaticCacheControl, Value: "public, max-age=31536000", Desc: "静态资源缓存设置 (Cache-Control)", Category: "服务"},
	{Key: consts.ConfigTrustedProxies, Value: "", Desc: "可信代理列表（逗号分隔，留空表示不信任代理头；修改后需重启服务生效）", Category: "安全"},
	{Key: consts.ConfigCaptchaProvider, Value: "image", Desc: "验证码提供方（空=关闭, image, turnstile, recaptcha, hcaptcha, geetest）", Category: "验证码"},
	{Key: consts.ConfigCaptchaTurnstileSiteKey, Value: "", Desc: "Cloudflare Turnstile Site Key", Category: "验证码"},
	{Key: consts.ConfigCaptchaTurnstileSecretKey, Value: "", Desc: "Cloudflare Turnstile Secret Key", Category: "验证码", Sensitive: true},
	{Key: consts.ConfigCaptchaTurnstileVerifyURL, Value: "", Desc: "Cloudflare Turnstile 校验地址，留空使用官方默认", Category: "验证码"},
	{Key: consts.ConfigCaptchaTurnstileExpectedHostname, Value: "", Desc: "Cloudflare Turnstile 期望回传域名（可选）", Category: "验证码"},
	{Key: consts.ConfigCaptchaRecaptchaSiteKey, Value: "", Desc: "Google reCAPTCHA Site Key", Category: "验证码"},
	{Key: consts.ConfigCaptchaRecaptchaSecretKey, Value: "", Desc: "Google reCAPTCHA Secret Key", Category: "验证码", Sensitive: true},
	{Key: consts.ConfigCaptchaRecaptchaVerifyURL, Value: "", Desc: "Google reCAPTCHA 校验地址，留空使用官方默认", Category: "验证码"},
	{Key: consts.ConfigCaptchaRecaptchaExpectedHostname, Value: "", Desc: "Google reCAPTCHA 期望回传域名（可选）", Category: "验证码"},
	{Key: consts.ConfigCaptchaHcaptchaSiteKey, Value: "", Desc: "hCaptcha Site Key", Category: "验证码"},
	{Key: consts.ConfigCaptchaHcaptchaSecretKey, Value: "", Desc: "hCaptcha Secret Key", Category: "验证码", Sensitive: true},
	{Key: consts.ConfigCaptchaHcaptchaVerifyURL, Value: "", Desc: "hCaptcha 校验地址，留空使用官方默认", Category: "验证码"},
	{Key: consts.ConfigCaptchaHcaptchaExpectedHostname, Value: "", Desc: "hCaptcha 期望回传域名（可选）", Category: "验证码"},
	{Key: consts.ConfigCaptchaGeetestCaptchaID, Value: "", Desc: "GeeTest Captcha ID", Category: "验证码"},
	{Key: consts.ConfigCaptchaGeetestCaptchaKey, Value: "", Desc: "GeeTest Captcha Key", Category: "验证码", Sensitive: true},
	{Key: consts.ConfigCaptchaGeetestVerifyURL, Value: "", Desc: "GeeTest 校验地址，留空使用官方默认", Category: "验证码"},
}

// ClearCache 清空设置缓存。
func ClearCache() {
	settingsCache.Range(func(key, value interface{}) bool {
		settingsCache.Delete(key)
		return true
	})
}

// InitializeSettings 将默认设置写入数据库，并同步描述与分类信息。
func InitializeSettings() {
	for _, def := range DefaultSettings {
		var count int64
		db.DB.Model(&model.Setting{}).Where("key = ?", def.Key).Count(&count)
		if count == 0 {
			db.DB.Create(&def)
		} else {
			// 同步更新 Category 和 Desc
			db.DB.Model(&model.Setting{}).Where("key = ?", def.Key).Updates(map[string]interface{}{
				"category":  def.Category,
				"desc":      def.Desc,
				"sensitive": def.Sensitive,
			})
		}
	}
}

// GetString 读取字符串配置值（优先缓存，其次数据库，最后默认值）。
func GetString(key string) string {
	if val, ok := settingsCache.Load(key); ok {
		strVal, ok := val.(string)
		if !ok {
			settingsCache.Delete(key)
		} else {
			if strVal == DefaultValueNotFound {
				return ""
			}
			return strVal
		}
	}

	var setting model.Setting
	if err := db.DB.Where("key = ?", key).First(&setting).Error; err != nil {
		// 数据库没查到，尝试查找默认配置
		for _, def := range DefaultSettings {
			if def.Key == key {
				// 查到了默认值，写入数据库并写入缓存
				newSetting := def
				// 尝试写入数据库 (忽略错误，防止并发写入导致的主键冲突)
				db.DB.Create(&newSetting)

				settingsCache.Store(key, newSetting.Value)
				return newSetting.Value
			}
		}

		// 没查到，往缓存里存 DefaultValueNotFound 标记
		settingsCache.Store(key, DefaultValueNotFound)
		return ""
	}
	// 数据库查到，写入缓存
	settingsCache.Store(key, setting.Value)

	return setting.Value
}

// GetInt 读取整型配置值。
func GetInt(key string) int {
	valStr := GetString(key)
	if valStr == "" {
		return 0
	}

	// 尝试转成 int
	val, err := strconv.Atoi(valStr)
	if err != nil {
		return 0
	}
	return val
}

// GetInt64 读取 int64 配置值。
func GetInt64(key string) int64 {
	valStr := GetString(key)
	if valStr == "" {
		return 0
	}

	// 尝试转成 int64
	val, err := strconv.ParseInt(valStr, 10, 64)
	if err != nil {
		return 0
	}
	return val
}

// GetFloat64 读取浮点型配置值。
func GetFloat64(key string) float64 {
	valStr := GetString(key)
	if valStr == "" {
		return 0
	}

	val, err := strconv.ParseFloat(valStr, 64)
	if err != nil {
		return 0
	}
	return val
}

// GetBool 读取布尔配置值。
func GetBool(key string) bool {
	valStr := GetString(key)
	if valStr == "" {
		return false
	}

	// ParseBool 支持 "1", "t", "T", "true", "TRUE", "True"
	val, err := strconv.ParseBool(valStr)
	if err != nil {
		return false
	}
	return val
}
