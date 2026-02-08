package service

import (
	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type InitPayload struct {
	Username        string
	Password        string
	SiteName        string
	SiteDescription string
}

// IsSystemInitialized 返回系统是否已完成初始化。
func IsSystemInitialized() bool {
	return !GetBool(consts.ConfigAllowInit)
}

// InitializeSystem 执行系统初始化：写入站点设置并创建管理员账号。
func InitializeSystem(payload InitPayload) error {
	passwordHashed, err := bcrypt.GenerateFromPassword([]byte(payload.Password), bcrypt.DefaultCost)
	if err != nil {
		return err
	}

	err = db.DB.Transaction(func(tx *gorm.DB) error {
		settingsToUpdate := map[string]string{
			consts.ConfigSiteName:        payload.SiteName,
			consts.ConfigSiteDescription: payload.SiteDescription,
			consts.ConfigAllowInit:       "false",
		}

		for key, value := range settingsToUpdate {
			if err := tx.Model(&model.Setting{}).Where("key = ?", key).Update("value", value).Error; err != nil {
				return err
			}
		}

		newUser := model.User{
			Username: payload.Username,
			Password: string(passwordHashed),
			Avatar:   "",
			Admin:    true,
		}
		if err := tx.Create(&newUser).Error; err != nil {
			return err
		}

		return nil
	})
	if err != nil {
		return err
	}

	ClearCache()
	return nil
}
