package service

import (
	"testing"

	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
)

// 测试内容：验证读取字符串设置时会插入默认值并与数据库一致。
func TestGetString_DefaultSettingInserted(t *testing.T) {
	setupTestDB(t)

	ClearCache()
	val := GetString(consts.ConfigSiteName)
	if val == "" {
		t.Fatalf("期望 default site_name to be non-empty")
	}

	var s model.Setting
	if err := db.DB.Where("key = ?", consts.ConfigSiteName).First(&s).Error; err != nil {
		t.Fatalf("期望 default setting row to be created: %v", err)
	}
	if s.Value != val {
		t.Fatalf("db value mismatch: got=%q 期望=%q", s.Value, val)
	}
}

// 测试内容：验证未知 key 返回空值且缓存未找到结果。
func TestGetString_UnknownKeyReturnsEmpty(t *testing.T) {
	setupTestDB(t)

	ClearCache()
	val := GetString("unknown_key_not_exists")
	if val != "" {
		t.Fatalf("期望 empty for unknown key，实际为 %q", val)
	}
	// 第二次调用仍应返回空值（缓存了未找到标记）。
	val2 := GetString("unknown_key_not_exists")
	if val2 != "" {
		t.Fatalf("期望 empty for unknown key，实际为 %q", val2)
	}
}

// 测试内容：验证整数配置解析失败时返回 0。
func TestGetInt_ParseFailureReturnsZero(t *testing.T) {
	db := setupTestDB(t)

	_ = db.Create(&model.Setting{Key: "k", Value: "not-int"}).Error
	ClearCache()

	if got := GetInt("k"); got != 0 {
		t.Fatalf("期望 0 for parse failure，实际为 %d", got)
	}
}

// 测试内容：验证浮点配置的正常解析与解析失败回退为 0。
func TestGetFloat64_ParseAndFailure(t *testing.T) {
	db := setupTestDB(t)

	_ = db.Create(&model.Setting{Key: "f1", Value: "0.5"}).Error
	_ = db.Create(&model.Setting{Key: "f2", Value: "bad"}).Error
	ClearCache()

	if got := GetFloat64("f1"); got != 0.5 {
		t.Fatalf("期望 0.5，实际为 %v", got)
	}
	if got := GetFloat64("f2"); got != 0 {
		t.Fatalf("期望 0 on parse 错误，实际为 %v", got)
	}
}
