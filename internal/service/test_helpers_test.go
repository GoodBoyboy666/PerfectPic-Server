package service

import (
	"testing"

	"perfect-pic-server/internal/testutils"

	"gorm.io/gorm"
)

func setupTestDB(t *testing.T) *gorm.DB {
	gdb := testutils.SetupDB(t)
	ClearCache()
	return gdb
}

func resetPasswordResetStore() {
	passwordResetStore.Range(func(key, value any) bool {
		passwordResetStore.Delete(key)
		return true
	})
}
