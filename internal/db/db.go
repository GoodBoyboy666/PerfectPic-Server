package db

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"perfect-pic-server/internal/config"
	"perfect-pic-server/internal/model"
	"time"

	"github.com/glebarez/sqlite"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func InitDB() {
	var err error
	cfg := config.Get()
	var dialector gorm.Dialector

	switch cfg.Database.Type {
	case "mysql":
		dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
			cfg.Database.User,
			cfg.Database.Password,
			cfg.Database.Host,
			cfg.Database.Port,
			cfg.Database.Name,
		)
		if cfg.Database.SSL {
			dsn += "&tls=true"
		}
		dialector = mysql.Open(dsn)
	case "postgres":
		sslMode := "disable"
		if cfg.Database.SSL {
			sslMode = "require"
		}
		dsn := fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s TimeZone=Asia/Shanghai",
			cfg.Database.Host,
			cfg.Database.User,
			cfg.Database.Password,
			cfg.Database.Name,
			cfg.Database.Port,
			sslMode,
		)
		dialector = postgres.Open(dsn)
	case "sqlite":
		fallthrough
	default:
		// 自动创建数据库目录
		dbDir := filepath.Dir(cfg.Database.Filename)
		if err := os.MkdirAll(dbDir, 0755); err != nil {
			log.Fatalf("❌ 无法创建数据库目录 '%s': %v", dbDir, err)
		}

		// 启用 WAL 模式和繁忙等待，提升 SQLite 并发性能
		dsn := cfg.Database.Filename + "?_foreign_keys=on&_journal_mode=WAL&_busy_timeout=5000"
		dialector = sqlite.Open(dsn)
	}

	DB, err = gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		log.Fatal("❌ 数据库连接失败: ", err)
	}

	// 获取底层 sql.DB 以配置连接池
	sqlDB, err := DB.DB()
	if err != nil {
		log.Fatal("❌ 无法获取 sql.DB: ", err)
	}

	// 配置连接池
	if cfg.Database.Type == "sqlite" {
		// SQLite 建议单连接写
		sqlDB.SetMaxOpenConns(1)
		sqlDB.SetMaxIdleConns(1)
	} else {
		// MySQL/PostgreSQL 可以支持更高并发
		sqlDB.SetMaxOpenConns(100)
		sqlDB.SetMaxIdleConns(10)
	}
	sqlDB.SetConnMaxLifetime(time.Hour)

	err = DB.AutoMigrate(
		&model.User{},
		&model.Setting{},
		&model.Image{},
	)

	if err != nil {
		log.Fatal("❌ 数据库迁移失败: ", err)
	}

	log.Printf("✅ 数据库(%s)连接成功，表结构已同步", cfg.Database.Type)
}
