package service

import (
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
)

// IsUsernameTaken 检查用户名是否已被占用。
// excludeUserID 用于更新场景下排除当前用户；includeDeleted 为 true 时会包含软删除用户。
func IsUsernameTaken(username string, excludeUserID *uint, includeDeleted bool) (bool, error) {
	return isUserFieldTaken("username", username, excludeUserID, includeDeleted)
}

// IsEmailTaken 检查邮箱是否已被占用。
// excludeUserID 用于更新场景下排除当前用户；includeDeleted 为 true 时会包含软删除用户。
func IsEmailTaken(email string, excludeUserID *uint, includeDeleted bool) (bool, error) {
	return isUserFieldTaken("email", email, excludeUserID, includeDeleted)
}

// isUserFieldTaken 按指定字段检查用户记录是否存在。
func isUserFieldTaken(field string, value string, excludeUserID *uint, includeDeleted bool) (bool, error) {
	query := db.DB.Model(&model.User{})
	if includeDeleted {
		query = query.Unscoped()
	}
	if excludeUserID != nil {
		query = query.Where("id != ?", *excludeUserID)
	}

	var count int64
	if err := query.Where(field+" = ?", value).Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}
