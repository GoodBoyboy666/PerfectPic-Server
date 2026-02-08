package service

import (
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"

	"gorm.io/gorm"
)

type PaginationQuery struct {
	Page     int
	PageSize int
}

type UserImageListParams struct {
	PaginationQuery
	UserID   uint
	Filename string
	ID       string
}

type AdminImageListParams struct {
	PaginationQuery
	Username string
	ID       string
}

// normalizePagination 归一化分页参数，确保页码与页大小有最小值。
func normalizePagination(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}
	return page, pageSize
}

// ListUserImages 分页查询用户自己的图片列表。
func ListUserImages(params UserImageListParams) ([]model.Image, int64, int, int, error) {
	page, pageSize := normalizePagination(params.Page, params.PageSize)

	var total int64
	var images []model.Image

	query := db.DB.Model(&model.Image{}).Where("user_id = ?", params.UserID)
	if params.Filename != "" {
		query = query.Where("filename LIKE ?", "%"+params.Filename+"%")
	}
	if params.ID != "" {
		query = query.Where("id = ?", params.ID)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, page, pageSize, err
	}

	if err := query.Order("id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&images).Error; err != nil {
		return nil, 0, page, pageSize, err
	}

	return images, total, page, pageSize, nil
}

// GetUserImageCount 获取用户图片总数。
func GetUserImageCount(userID uint) (int64, error) {
	var count int64
	if err := db.DB.Model(&model.Image{}).Where("user_id = ?", userID).Count(&count).Error; err != nil {
		return 0, err
	}
	return count, nil
}

// GetUserOwnedImage 获取用户名下的指定图片，用于鉴权后的删除/查看。
func GetUserOwnedImage(imageID string, userID uint) (*model.Image, error) {
	var image model.Image
	if err := db.DB.Where("id = ? AND user_id = ?", imageID, userID).First(&image).Error; err != nil {
		return nil, err
	}
	return &image, nil
}

// GetImagesByIDsForUser 按 ID 列表获取用户名下图片（批量场景）。
func GetImagesByIDsForUser(ids []uint, userID uint) ([]model.Image, error) {
	var images []model.Image
	if err := db.DB.Where("id IN ? AND user_id = ?", ids, userID).Find(&images).Error; err != nil {
		return nil, err
	}
	return images, nil
}

// ListImagesForAdmin 分页查询后台图片列表，支持按用户名与图片 ID 过滤。
func ListImagesForAdmin(params AdminImageListParams) ([]model.Image, int64, int, int, error) {
	page, pageSize := normalizePagination(params.Page, params.PageSize)

	var total int64
	var images []model.Image

	query := db.DB.Model(&model.Image{})
	if params.Username != "" {
		query = query.Joins("JOIN users ON users.id = images.user_id").Where("users.username LIKE ?", "%"+params.Username+"%")
	}
	if params.ID != "" {
		query = query.Where("images.id = ?", params.ID)
	}

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, page, pageSize, err
	}

	if err := query.Preload("User").Order("images.id desc").Offset((page - 1) * pageSize).Limit(pageSize).Find(&images).Error; err != nil {
		return nil, 0, page, pageSize, err
	}

	return images, total, page, pageSize, nil
}

// GetImageByIDForAdmin 获取后台指定图片。
func GetImageByIDForAdmin(id string) (*model.Image, error) {
	var image model.Image
	if err := db.DB.First(&image, id).Error; err != nil {
		return nil, err
	}
	return &image, nil
}

// GetImagesByIDsForAdmin 按 ID 列表获取后台图片。
func GetImagesByIDsForAdmin(ids []uint) ([]model.Image, error) {
	var images []model.Image
	if err := db.DB.Where("id IN ?", ids).Find(&images).Error; err != nil {
		return nil, err
	}
	return images, nil
}

// IsRecordNotFound 判断错误是否为记录不存在。
func IsRecordNotFound(err error) bool {
	return err == gorm.ErrRecordNotFound
}
