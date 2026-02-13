package service

import (
	"fmt"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/utils"
	"runtime"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type AdminUserListParams struct {
	Page        int
	PageSize    int
	Keyword     string
	ShowDeleted bool
	Order       string
}

type AdminUserUpdateInput struct {
	Username      *string
	Password      *string
	Email         *string
	EmailVerified *bool
	StorageQuota  *int64
	Status        *int
}

type AdminCreateUserInput struct {
	Username      string
	Password      string
	Email         *string
	EmailVerified *bool
	StorageQuota  *int64
	Status        *int
}

type UpdateSettingPayload struct {
	Key   string
	Value string
}

type SystemInfo struct {
	OS           string `json:"os"`
	Arch         string `json:"arch"`
	GoVersion    string `json:"go_version"`
	NumCPU       int    `json:"num_cpu"`
	NumGoroutine int    `json:"num_goroutine"`
}

type ServerStats struct {
	ImageCount   int64      `json:"image_count"`
	StorageUsage int64      `json:"storage_usage"`
	UserCount    int64      `json:"user_count"`
	SystemInfo   SystemInfo `json:"system_info"`
}

// GetServerStatsForAdmin 获取后台仪表盘统计数据。
func GetServerStatsForAdmin() (*ServerStats, error) {
	var imageCount int64
	var totalSize int64
	var userCount int64

	if err := db.DB.Model(&model.Image{}).Count(&imageCount).Error; err != nil {
		return nil, err
	}

	if err := db.DB.Model(&model.Image{}).Select("COALESCE(SUM(size), 0)").Scan(&totalSize).Error; err != nil {
		return nil, err
	}

	if err := db.DB.Model(&model.User{}).Count(&userCount).Error; err != nil {
		return nil, err
	}

	return &ServerStats{
		ImageCount:   imageCount,
		StorageUsage: totalSize,
		UserCount:    userCount,
		SystemInfo: SystemInfo{
			OS:           runtime.GOOS,
			Arch:         runtime.GOARCH,
			GoVersion:    runtime.Version(),
			NumCPU:       runtime.NumCPU(),
			NumGoroutine: runtime.NumGoroutine(),
		},
	}, nil
}

// ListSettingsForAdmin 获取全部系统设置。
func ListSettingsForAdmin() ([]model.Setting, error) {
	var settings []model.Setting
	if err := db.DB.Find(&settings).Error; err != nil {
		return nil, err
	}

	// 脱敏处理
	for i := range settings {
		if settings[i].Sensitive {
			settings[i].Value = "**********"
		}
	}

	return settings, nil
}

// UpdateSettingsForAdmin 批量更新系统设置，并在成功后清理配置缓存。
func UpdateSettingsForAdmin(items []UpdateSettingPayload) error {
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		for _, item := range items {
			// 如果值为mask且是敏感字段，则不更新
			if item.Value == "**********" {
				var currentSetting model.Setting
				if err := tx.Where("key = ?", item.Key).First(&currentSetting).Error; err == nil {
					if currentSetting.Sensitive {
						continue
					}
				}
			}

			setting := model.Setting{Key: item.Key, Value: item.Value}

			result := tx.Model(&setting).Select("Value").Updates(setting)
			if result.Error != nil {
				return result.Error
			}

			if result.RowsAffected == 0 {
				if err := tx.Create(&setting).Error; err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return err
	}

	ClearCache()
	return nil
}

// ListUsersForAdmin 按分页与筛选条件查询用户列表。
func ListUsersForAdmin(params AdminUserListParams) ([]model.User, int64, error) {
	page := params.Page
	pageSize := params.PageSize
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}

	var users []model.User
	var total int64

	query := db.DB.Model(&model.User{})
	if params.ShowDeleted {
		query = query.Unscoped()
	}
	if strings.TrimSpace(params.Keyword) != "" {
		query = query.Where("username LIKE ?", "%"+params.Keyword+"%")
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	sortOrder := "id desc"
	if params.Order == "asc" {
		sortOrder = "id asc"
	}

	if err := query.Offset((page - 1) * pageSize).Limit(pageSize).Order(sortOrder).Find(&users).Error; err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

// GetUserDetailForAdmin 根据用户 ID 获取详情。
func GetUserDetailForAdmin(id uint) (*model.User, error) {
	var user model.User
	if err := db.DB.First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

// CreateUserForAdmin 创建后台普通用户。
//
//nolint:gocyclo // 管理员创建用户场景校验分支较多，后续再拆分
func CreateUserForAdmin(input AdminCreateUserInput) (*model.User, string, error) {
	if ok, msg := utils.ValidatePassword(input.Password); !ok {
		return nil, msg, nil
	}

	if ok, msg := utils.ValidateUsername(input.Username); !ok {
		return nil, msg, nil
	}

	usernameTaken, err := IsUsernameTaken(input.Username, nil, true)
	if err != nil {
		return nil, "", err
	}
	if usernameTaken {
		return nil, "用户名已存在", nil
	}

	if input.Email != nil && *input.Email != "" {
		if ok, msg := utils.ValidateEmail(*input.Email); !ok {
			return nil, msg, nil
		}

		emailTaken, emailErr := IsEmailTaken(*input.Email, nil, true)
		if emailErr != nil {
			return nil, "", emailErr
		}
		if emailTaken {
			return nil, "邮箱已被注册", nil
		}
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)
	if err != nil {
		return nil, "", err
	}

	user := model.User{
		Username: input.Username,
		Password: string(hashedPassword),
		Admin:    false,
		Status:   1,
	}

	if input.Email != nil {
		user.Email = *input.Email
	}

	if input.EmailVerified != nil {
		user.EmailVerified = *input.EmailVerified
	}

	if input.StorageQuota != nil {
		if *input.StorageQuota == -1 {
			user.StorageQuota = nil
		} else if *input.StorageQuota >= 0 {
			quota := *input.StorageQuota
			user.StorageQuota = &quota
		} else {
			return nil, "存储配额不能为负数（-1除外）", nil
		}
	}

	if input.Status != nil {
		if *input.Status == 1 || *input.Status == 2 {
			user.Status = *input.Status
		} else {
			return nil, "无效的用户状态", nil
		}
	}

	if err := db.DB.Create(&user).Error; err != nil {
		return nil, "", err
	}

	return &user, "", nil
}

// PrepareUserUpdatesForAdmin 校验后台用户更新输入并构建可持久化的 updates。
//
//nolint:gocyclo // 管理员更新用户场景校验分支较多，后续再拆分
func PrepareUserUpdatesForAdmin(userID uint, req AdminUserUpdateInput) (map[string]interface{}, string, error) {
	updates := make(map[string]interface{})

	if req.Username != nil && *req.Username != "" {
		if ok, msg := utils.ValidateUsername(*req.Username); !ok {
			return nil, msg, nil
		}
		excludeID := userID
		usernameTaken, err := IsUsernameTaken(*req.Username, &excludeID, true)
		if err != nil {
			return nil, "", err
		}
		if usernameTaken {
			return nil, "该用户名已被其他用户占用", nil
		}

		updates["username"] = *req.Username
	}

	if req.Password != nil && *req.Password != "" {
		if ok, msg := utils.ValidatePassword(*req.Password); !ok {
			return nil, msg, nil
		}
		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(*req.Password), bcrypt.DefaultCost)
		if err != nil {
			return nil, "", err
		}
		updates["password"] = string(hashedPassword)
	}

	if req.Email != nil && *req.Email != "" {
		if ok, msg := utils.ValidateEmail(*req.Email); !ok {
			return nil, msg, nil
		}
		excludeID := userID
		emailTaken, err := IsEmailTaken(*req.Email, &excludeID, true)
		if err != nil {
			return nil, "", err
		}
		if emailTaken {
			return nil, "该邮箱已被其他用户占用", nil
		}

		updates["email"] = *req.Email
	}

	if req.EmailVerified != nil {
		updates["email_verified"] = *req.EmailVerified
	}

	if req.StorageQuota != nil {
		if *req.StorageQuota == -1 {
			updates["storage_quota"] = nil
		} else if *req.StorageQuota >= 0 {
			updates["storage_quota"] = *req.StorageQuota
		} else {
			return nil, "存储配额不能为负数（-1除外）", nil
		}
	}

	if req.Status != nil {
		if *req.Status == 1 || *req.Status == 2 {
			updates["status"] = *req.Status
		} else {
			return nil, "无效的用户状态", nil
		}
	}

	return updates, "", nil
}

// ApplyUserUpdatesForAdmin 将更新字段应用到指定用户。
func ApplyUserUpdatesForAdmin(userID uint, updates map[string]interface{}) error {
	if len(updates) == 0 {
		return nil
	}

	var user model.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		return err
	}

	if err := db.DB.Model(&user).Updates(updates).Error; err != nil {
		return err
	}

	return nil
}

// DeleteUserForAdmin 删除用户。
// hardDelete=true 时执行彻底删除；否则执行软删除并清理唯一字段占用。
func DeleteUserForAdmin(userID uint, hardDelete bool) error {
	if hardDelete {
		if err := DeleteUserFiles(userID); err != nil {
			return err
		}

		return db.DB.Transaction(func(tx *gorm.DB) error {
			var user model.User
			if err := tx.Unscoped().First(&user, userID).Error; err != nil {
				return err
			}
			return tx.Unscoped().Delete(&user).Error
		})
	}

	return db.DB.Transaction(func(tx *gorm.DB) error {
		var user model.User
		if err := tx.First(&user, userID).Error; err != nil {
			return err
		}

		timestamp := time.Now().Unix()
		newUsername := fmt.Sprintf("%s_del_%d", user.Username, timestamp)
		newEmail := fmt.Sprintf("del_%d_%s", timestamp, user.Email)
		if len(newEmail) > 255 {
			newEmail = newEmail[:255]
		}

		if err := tx.Model(&user).Updates(map[string]interface{}{
			"username": newUsername,
			"email":    newEmail,
			"status":   3,
		}).Error; err != nil {
			return err
		}

		return tx.Delete(&user).Error
	})
}
