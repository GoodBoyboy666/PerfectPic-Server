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

//nolint:gocyclo
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

	// SQLite 的外键约束默认是关闭的（且是“按连接”生效）。
	// 这里显式开启，避免 DSN 参数在不同 driver/场景下未生效导致级联删除不工作。
	if cfg.Database.Type == "sqlite" {
		if err := DB.Exec("PRAGMA foreign_keys = ON").Error; err != nil {
			log.Fatal("❌ 无法启用 SQLite 外键约束(PRAGMA foreign_keys=ON): ", err)
		}
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

	if cfg.Database.Type == "sqlite" {
		// 仅提示：如果数据库是旧版本、images 表曾在没有外键约束的情况下创建，
		// SQLite 的 ALTER TABLE 能力有限，AutoMigrate 可能无法补上外键与 ON DELETE CASCADE。
		type fkRow struct {
			Table    string `gorm:"column:table"`
			From     string `gorm:"column:from"`
			To       string `gorm:"column:to"`
			OnDelete string `gorm:"column:on_delete"`
		}
		var fks []fkRow
		if err := DB.Raw("PRAGMA foreign_key_list(images)").Scan(&fks).Error; err == nil {
			hasCascade := false
			for _, fk := range fks {
				if fk.Table == "users" && fk.From == "user_id" && fk.To == "id" && fk.OnDelete == "CASCADE" {
					hasCascade = true
					break
				}
			}
			if !hasCascade {
				log.Printf("⚠️ SQLite 表 images 未检测到 user_id -> users(id) 的 ON DELETE CASCADE 外键；硬删除用户时图片记录可能不会被级联删除。建议重建 images 表或重新初始化数据库文件。")
			}
		}
	}

	log.Printf("✅ 数据库(%s)连接成功，表结构已同步", cfg.Database.Type)
}
