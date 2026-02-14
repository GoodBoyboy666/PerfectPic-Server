package testutils

import (
	"fmt"
	"sync/atomic"
	"testing"

	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"

	"github.com/glebarez/sqlite"
	"gorm.io/gorm"
)

var testDBSeq int64

// SetupDB initializes a unique in-memory SQLite database for testing,
// sets the global db.DB, and performs auto-migration.
// It DOES NOT clear the service cache (to avoid circular dependencies).
// Callers should call service.ClearCache() if needed.
func SetupDB(t *testing.T) *gorm.DB {
	t.Helper()

	seq := atomic.AddInt64(&testDBSeq, 1)
	dsn := fmt.Sprintf("file:ppt_%d?mode=memory&cache=shared", seq)
	gdb, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	sqlDB, err := gdb.DB()
	if err != nil {
		t.Fatalf("get sql db: %v", err)
	}
	sqlDB.SetMaxOpenConns(1)
	sqlDB.SetMaxIdleConns(1)

	prevDB := db.DB
	t.Cleanup(func() {
		if prevDB != nil && db.DB == gdb {
			db.DB = prevDB
		}
		_ = sqlDB.Close()
	})

	if err := gdb.AutoMigrate(&model.User{}, &model.Setting{}, &model.Image{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}

	db.DB = gdb
	return gdb
}
