package config

import (
	"log"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"
)

// 用于管理应用配置，支持热重载

var (
	// 使用 atomic.Value 存储 *Config，实现无锁读取
	appConfig atomic.Value
	configMu  sync.Mutex // 仅用于写操作互斥
)

type Config struct {
	Server   ServerConfig   `mapstructure:"server"`
	Database DatabaseConfig `mapstructure:"database"`
	JWT      JWTConfig      `mapstructure:"jwt"`
	Upload   UploadConfig   `mapstructure:"upload"`
	SMTP     SMTPConfig     `mapstructure:"smtp"`
}

type ServerConfig struct {
	Port string `mapstructure:"port"`
	Mode string `mapstructure:"mode"`
}

type DatabaseConfig struct {
	Type     string `mapstructure:"type"`     // sqlite, mysql, postgres
	Filename string `mapstructure:"filename"` // for sqlite
	Host     string `mapstructure:"host"`
	Port     string `mapstructure:"port"`
	User     string `mapstructure:"user"`
	Password string `mapstructure:"password"`
	Name     string `mapstructure:"name"` // database name
	SSL      bool   `mapstructure:"ssl"`  // enable TLS/SSL
}

type JWTConfig struct {
	Secret          string `mapstructure:"secret"`
	ExpirationHours int    `mapstructure:"expiration_hours"`
}

type UploadConfig struct {
	Path            string `mapstructure:"path"`
	URLPrefix       string `mapstructure:"url_prefix"`
	AvatarPath      string `mapstructure:"avatar_path"`
	AvatarURLPrefix string `mapstructure:"avatar_url_prefix"`
}

type SMTPConfig struct {
	Host     string `mapstructure:"host"`
	Port     int    `mapstructure:"port"`
	Username string `mapstructure:"username"`
	Password string `mapstructure:"password"`
	From     string `mapstructure:"from"`
	SSL      bool   `mapstructure:"ssl"`
}

// Get 获取当前配置的快照（高性能无锁）
func Get() Config {
	val := appConfig.Load()
	if val == nil {
		return Config{}
	}
	c, ok := val.(*Config)
	if !ok {
		return Config{}
	}
	return *c
}

func InitConfig() {
	v := viper.New()

	// 设置配置文件路径
	v.AddConfigPath("config")
	v.AddConfigPath(".")
	v.SetConfigName("config")
	v.SetConfigType("yaml")

	// 设置默认值
	v.SetDefault("upload.path", "uploads/imgs")
	v.SetDefault("upload.url_prefix", "/imgs/")
	v.SetDefault("upload.avatar_path", "uploads/avatars")
	v.SetDefault("upload.avatar_url_prefix", "/avatars/")
	v.SetDefault("server.port", "8080")
	v.SetDefault("server.mode", "debug")
	v.SetDefault("database.type", "sqlite")
	v.SetDefault("database.filename", "config/perfect_pic.db")
	v.SetDefault("database.host", "127.0.0.1")
	v.SetDefault("database.port", "3306")
	v.SetDefault("database.user", "root")
	v.SetDefault("database.password", "root")
	v.SetDefault("database.name", "perfect_pic")
	v.SetDefault("database.ssl", false)
	v.SetDefault("jwt.secret", "")
	v.SetDefault("jwt.expiration_hours", 24)
	v.SetDefault("smtp.host", "")
	v.SetDefault("smtp.port", 587)
	v.SetDefault("smtp.username", "")
	v.SetDefault("smtp.password", "")
	v.SetDefault("smtp.from", "")
	v.SetDefault("smtp.ssl", false)

	// 读取配置文件
	if err := v.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			log.Println("⚠️  未找到配置文件，将仅使用环境变量或默认值")
		} else {
			log.Fatalf("❌ 读取配置文件失败: %v", err)
		}
	}

	// 配置环境变量覆盖
	// 规则：所有环境变量必须以 PERFECT_PIC_ 开头
	// 例如：yaml 中的 server.port 对应环境变量 PERFECT_PIC_SERVER_PORT
	v.SetEnvPrefix("PERFECT_PIC")

	// 允许自动查找环境变量
	v.AutomaticEnv()

	// 解决层级分隔符问题：将 key 中的 "." 替换为 "_"
	// 这样 server.port 才能匹配 SERVER_PORT
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// 初始加载配置
	loadAndStore(v)

	// 首次启动安全检查：如果是 release 模式，拦截不安全的 JWT Secret
	curr := Get()
	if curr.Server.Mode == "release" {
		if curr.JWT.Secret == "" || curr.JWT.Secret == "perfect_pic_secret" {
			log.Fatal("❌ [安全严重错误] 生产模式(release)下必须设置安全的 JWT Secret！\n请设置环境变量 PERFECT_PIC_JWT_SECRET 或在配置文件中指定 jwt.secret")
		}
	}

	v.WatchConfig()
	v.OnConfigChange(func(e fsnotify.Event) {
		log.Println("🔄 检测到配置文件变化:", e.Name)
		loadAndStore(v)
	})

	log.Println("✅ 配置加载成功")
}

// loadAndStore 解析并原子更新配置
func loadAndStore(v *viper.Viper) {
	// 加写锁，防止并发重载时的竞争
	configMu.Lock()
	defer configMu.Unlock()

	var tempConfig Config
	// 将配置映射到结构体
	if err := v.Unmarshal(&tempConfig); err != nil {
		log.Printf("❌ 配置解析失败: %v", err)
		return
	}

	// 安全检查
	if tempConfig.Server.Mode == "release" {
		if tempConfig.JWT.Secret == "" || tempConfig.JWT.Secret == "perfect_pic_secret" {
			log.Println("❌ [安全严重错误] 生产模式(release)下必须设置安全的 JWT Secret！")
		}
	} else {
		if tempConfig.JWT.Secret == "" {
			log.Println("⚠️ [开发模式警告] 未设置 JWT Secret，将使用默认不安全密钥进行开发")
			tempConfig.JWT.Secret = "perfect_pic_secret"
		}
	}

	// 原子替换全局配置
	appConfig.Store(&tempConfig)
	log.Println("✅ 配置已更新")
}
