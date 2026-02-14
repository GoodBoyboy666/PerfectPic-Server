package middleware

import (
	"testing"

	"perfect-pic-server/internal/service"
	"perfect-pic-server/internal/testutils"

	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	gdb := testutils.SetupDB(t)
	service.ClearCache()
	return gdb
}

func resetStatusCache() {
	statusCache.Range(func(key, value any) bool {
		statusCache.Delete(key)
		return true
	})
}
