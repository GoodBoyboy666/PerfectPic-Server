package service

import (
	"errors"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"os"
	"path/filepath"
	"perfect-pic-server/internal/config"
	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/utils"
	"strings"
	"time"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ValidateImageFile 验证上传的图片文件（大小、后缀、内容）
// 返回:
//   - bool: 是否合法
//   - string: 文件扩展名 (小写, 如 .jpg)
//   - error: 错误信息或原因
func ValidateImageFile(file *multipart.FileHeader) (bool, string, error) {
	// 检查文件大小
	maxSizeMB := GetInt(consts.ConfigMaxUploadSize) // 默认 10MB
	if file.Size > int64(maxSizeMB*1024*1024) {
		return false, "", fmt.Errorf("文件大小不能超过 %dMB", maxSizeMB)
	}

	// 检查文件扩展名
	allowExtsStr := GetString(consts.ConfigAllowFileExtensions)
	ext := strings.ToLower(filepath.Ext(file.Filename))
	if ext == "" {
		return false, "", errors.New("无法识别文件类型")
	}

	allowed := false
	for _, allowExt := range strings.Split(allowExtsStr, ",") {
		if strings.TrimSpace(strings.ToLower(allowExt)) == ext {
			allowed = true
			break
		}
	}
	if !allowed {
		return false, ext, fmt.Errorf("不支持的文件类型: %s", ext)
	}

	// 检查文件内容 (Magic Bytes)
	src, err := file.Open()
	if err != nil {
		return false, ext, errors.New("无法打开上传的文件")
	}
	defer func() { _ = src.Close() }()

	if valid, msg := utils.ValidateImageContent(src, ext); !valid {
		return false, ext, errors.New(msg)
	}

	return true, ext, nil
}

// ProcessImageUpload 处理图片上传核心业务
// 包括：配额检查、文件保存、数据库记录
//
//nolint:gocyclo
func ProcessImageUpload(file *multipart.FileHeader, uid uint) (*model.Image, string, error) {
	// 验证文件
	valid, ext, err := ValidateImageFile(file)
	if !valid {
		return nil, "", err
	}

	// 检查配额 (使用 StorageUsed 字段)
	var user model.User
	if err := db.DB.First(&user, uid).Error; err != nil {
		log.Printf("Get user error: %v\n", err)
		return nil, "", errors.New("查询用户信息失败")
	}

	// 如果 StorageUsed 为 0 但不是新用户，可能需要同步
	usedSize := user.StorageUsed

	var quota int64
	if user.StorageQuota != nil {
		quota = *user.StorageQuota
	} else {
		quota = GetInt64(consts.ConfigDefaultStorageQuota)
		if quota == 0 {
			quota = 1073741824 // 1GB
		}
	}

	if usedSize+file.Size > quota {
		return nil, "", fmt.Errorf("存储空间不足，上传失败。当前已用: %d B, 剩余: %d B", usedSize, quota-usedSize)
	}

	// 准备路径
	now := time.Now()
	datePath := filepath.Join(now.Format("2006"), now.Format("01"), now.Format("02"))

	cfg := config.Get()
	uploadRoot := cfg.Upload.Path
	if uploadRoot == "" {
		uploadRoot = "uploads/imgs"
	}
	uploadRootAbs, err := filepath.Abs(uploadRoot)
	if err != nil {
		return nil, "", errors.New("系统错误: 上传目录解析失败")
	}
	// 先检查上传根目录节点本身不是符号链接（防止根目录直接指向外部路径）。
	if err := utils.EnsurePathNotSymlink(uploadRootAbs); err != nil {
		log.Printf("Upload root security check failed: %v\n", err)
		return nil, "", errors.New("系统错误: 上传目录存在符号链接风险")
	}
	// 完整的磁盘文件夹路径
	fullDir, err := utils.SecureJoin(uploadRootAbs, datePath)
	if err != nil {
		log.Printf("SecureJoin dir error: %v\n", err)
		return nil, "", errors.New("系统错误: 非法存储目录")
	}

	// 自动创建文件夹
	if err := os.MkdirAll(fullDir, 0755); err != nil {
		log.Printf("MkdirAll error: %v\n", err)
		return nil, "", errors.New("系统错误: 无法创建存储目录")
	}
	// 目录创建后再次检查链路，降低 TOCTOU 风险。
	if err := utils.EnsureNoSymlinkBetween(uploadRootAbs, fullDir); err != nil {
		log.Printf("Upload dir security check failed: %v\n", err)
		return nil, "", errors.New("系统错误: 存储目录存在符号链接风险")
	}

	// 生成唯一文件名
	newFilename := uuid.New().String() + ext
	dst, err := utils.SecureJoin(fullDir, newFilename)
	if err != nil {
		log.Printf("SecureJoin dst error: %v\n", err)
		return nil, "", errors.New("系统错误: 非法文件路径")
	}

	// 保存文件 (IO 操作放在事务前，如果 DB 失败则删除文件)
	src, err := file.Open()
	if err != nil {
		return nil, "", errors.New("无法读取上传文件")
	}
	defer func() { _ = src.Close() }()

	out, err := os.Create(dst)
	if err != nil {
		return nil, "", errors.New("系统错误: 无法创建文件")
	}
	defer func() { _ = out.Close() }()

	if _, err = io.Copy(out, src); err != nil {
		return nil, "", errors.New("文件保存失败")
	}

	// 数据库操作 (事务)
	relativePath := filepath.ToSlash(filepath.Join(
		now.Format("2006"), now.Format("01"), now.Format("02"), newFilename))

	imageRecord := model.Image{
		Filename:   newFilename,
		Path:       relativePath,
		Size:       file.Size,
		UserID:     uid,
		UploadedAt: now.Unix(),
		MimeType:   ext,
	}

	err = db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(&imageRecord).Error; err != nil {
			return err
		}
		// 增加已用空间
		if err := tx.Model(&model.User{}).Where("id = ?", uid).
			UpdateColumn("storage_used", gorm.Expr("storage_used + ?", file.Size)).Error; err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		_ = os.Remove(dst) // 回滚文件
		log.Printf("Process upload DB error: %v\n", err)
		return nil, "", errors.New("系统错误: 数据库记录失败")
	}

	return &imageRecord, cfg.Upload.URLPrefix + relativePath, nil
}

// DeleteImage 删除图片文件和数据库记录
func DeleteImage(image *model.Image) error {
	cfg := config.Get()
	uploadRoot := cfg.Upload.Path
	if uploadRoot == "" {
		uploadRoot = "uploads/imgs"
	}
	uploadRootAbs, err := filepath.Abs(uploadRoot)
	if err != nil {
		return errors.New("系统错误: 上传目录解析失败")
	}
	// 删除前先校验上传根目录节点本身，避免根目录被替换为符号链接。
	if err := utils.EnsurePathNotSymlink(uploadRootAbs); err != nil {
		log.Printf("DeleteImage upload root security check failed: %v\n", err)
		return errors.New("系统错误: 上传目录存在符号链接风险")
	}

	// 拼接完整物理路径
	fullPath, err := utils.SecureJoin(uploadRootAbs, image.Path)
	if err != nil {
		log.Printf("DeleteImage secure path error: %v\n", err)
		return errors.New("系统错误: 非法文件路径")
	}

	// 使用事务确保数据库操作原子性
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Delete(image).Error; err != nil {
			return err
		}
		// 减少用户已用存储空间
		if err := tx.Model(&model.User{}).Where("id = ?", image.UserID).
			UpdateColumn("storage_used", gorm.Expr("storage_used - ?", image.Size)).Error; err != nil {
			return err
		}
		return nil
	})

	if err != nil {
		return err
	}

	// 事务提交后，删除物理文件
	if err := os.Remove(fullPath); err != nil {
		if !os.IsNotExist(err) {
			log.Printf("Delete file error: %v, path: %s\n", err, fullPath)
		}
	}

	return nil
}

// BatchDeleteImages 批量删除图片
func BatchDeleteImages(images []model.Image) error {
	if len(images) == 0 {
		return nil
	}

	// 使用 map 按用户分组统计待释放的空间
	// key: UserID, value: TotalSizeToFree
	userSizeMap := make(map[uint]int64)
	var imageIDs []uint
	var pathsToDelete []string

	cfg := config.Get()
	uploadRoot := cfg.Upload.Path
	if uploadRoot == "" {
		uploadRoot = "uploads/imgs"
	}
	uploadRootAbs, err := filepath.Abs(uploadRoot)
	if err != nil {
		return errors.New("系统错误: 上传目录解析失败")
	}
	// 批量删除前先校验上传根目录节点本身，避免根目录被替换为符号链接。
	if err := utils.EnsurePathNotSymlink(uploadRootAbs); err != nil {
		log.Printf("BatchDeleteImages upload root security check failed: %v\n", err)
		return errors.New("系统错误: 上传目录存在符号链接风险")
	}

	for _, img := range images {
		userSizeMap[img.UserID] += img.Size
		imageIDs = append(imageIDs, img.ID)
		fullPath, secureErr := utils.SecureJoin(uploadRootAbs, img.Path)
		if secureErr != nil {
			log.Printf("BatchDeleteImages secure path error: %v\n", secureErr)
			continue
		}
		pathsToDelete = append(pathsToDelete, fullPath)
	}

	// 开启单一事务处理所有数据库变更
	err = db.DB.Transaction(func(tx *gorm.DB) error {
		// 批量删除图片记录
		if err := tx.Where("id IN ?", imageIDs).Delete(&model.Image{}).Error; err != nil {
			return err
		}

		// 按用户分别更新已用存储空间
		// 即使是管理员批量删除不同用户的图片，这里也只会有 N 个 UPDATE 语句 (N = 涉及的用户数量)
		for uid, size := range userSizeMap {
			if err := tx.Model(&model.User{}).Where("id = ?", uid).
				UpdateColumn("storage_used", gorm.Expr("storage_used - ?", size)).Error; err != nil {
				return err
			}
		}
		return nil
	})

	if err != nil {
		return err
	}

	// 事务成功提交后，清理物理文件
	for _, path := range pathsToDelete {
		if err := os.Remove(path); err != nil {
			if !os.IsNotExist(err) {
				log.Printf("Batch delete file error: %v, path: %s\n", err, path)
			}
		}
	}

	return nil
}

// UpdateUserAvatar 更新用户头像
func UpdateUserAvatar(user *model.User, file *multipart.FileHeader) (string, error) {
	cfg := config.Get()
	avatarRoot := cfg.Upload.AvatarPath
	if avatarRoot == "" {
		avatarRoot = "uploads/avatars"
	}
	avatarRootAbs, err := filepath.Abs(avatarRoot)
	if err != nil {
		return "", errors.New("系统错误: 头像目录解析失败")
	}
	// 先检查头像根目录节点本身不是符号链接。
	if err := utils.EnsurePathNotSymlink(avatarRootAbs); err != nil {
		log.Printf("Avatar root security check failed: %v\n", err)
		return "", errors.New("系统错误: 头像目录存在符号链接风险")
	}

	ext := strings.ToLower(filepath.Ext(file.Filename))
	// userIdStr for path
	userIdStr := fmt.Sprintf("%v", user.ID)
	storageDir, err := utils.SecureJoin(avatarRootAbs, userIdStr)
	if err != nil {
		log.Printf("Avatar storage dir error: %v\n", err)
		return "", errors.New("系统错误: 非法头像目录")
	}

	// 自动创建文件夹
	if err := os.MkdirAll(storageDir, 0755); err != nil {
		log.Printf("MkdirAll error: %v\n", err)
		return "", errors.New("系统错误: 无法创建存储目录")
	}
	// 用户目录创建后再次检查链路，确保新增层级未被符号链接替换。
	if err := utils.EnsureNoSymlinkBetween(avatarRootAbs, storageDir); err != nil {
		log.Printf("Avatar storage security check failed: %v\n", err)
		return "", errors.New("系统错误: 头像目录存在符号链接风险")
	}

	// 生成唯一文件名
	newFilename := uuid.New().String() + ext
	dstPath, err := utils.SecureJoin(storageDir, newFilename)
	if err != nil {
		log.Printf("Avatar dst secure join error: %v\n", err)
		return "", errors.New("系统错误: 非法头像文件路径")
	}

	// 打开源文件
	src, err := file.Open()
	if err != nil {
		log.Printf("File open error: %v\n", err)
		return "", errors.New("无法读取上传文件")
	}
	defer func() { _ = src.Close() }()

	// 创建目标文件
	out, err := os.Create(dstPath)
	if err != nil {
		log.Printf("File create error: %v\n", err)
		return "", errors.New("系统错误: 无法创建文件")
	}
	defer func() { _ = out.Close() }()

	// 复制内容
	if _, err = io.Copy(out, src); err != nil {
		log.Printf("File save error: %v\n", err)
		return "", errors.New("文件保存失败")
	}

	// 保存旧头像文件名用于后续删除
	oldAvatar := user.Avatar

	// 更新数据库
	if err := db.DB.Model(user).Update("avatar", newFilename).Error; err != nil {
		_ = os.Remove(dstPath) // 回滚文件
		log.Printf("DB Update avatar error: %v\n", err)
		return "", errors.New("系统错误: 数据库更新失败")
	}

	// 删除旧头像
	if oldAvatar != "" {
		oldAvatarPath, secureErr := utils.SecureJoin(storageDir, oldAvatar)
		if secureErr != nil {
			log.Printf("Old avatar secure path error: %v\n", secureErr)
		} else {
			_ = os.Remove(oldAvatarPath)
		}
	}

	return newFilename, nil
}

// RemoveUserAvatar 移除用户头像
func RemoveUserAvatar(user *model.User) error {
	// 如果用户没有头像，直接返回
	if user.Avatar == "" {
		return nil
	}

	cfg := config.Get()
	avatarRoot := cfg.Upload.AvatarPath
	if avatarRoot == "" {
		avatarRoot = "uploads/avatars"
	}
	avatarRootAbs, err := filepath.Abs(avatarRoot)
	if err != nil {
		return errors.New("系统错误: 头像目录解析失败")
	}
	// 删除头像前先校验头像根目录节点本身，防止根目录符号链接穿透。
	if err := utils.EnsurePathNotSymlink(avatarRootAbs); err != nil {
		log.Printf("RemoveUserAvatar root security check failed: %v\n", err)
		return errors.New("系统错误: 头像目录存在符号链接风险")
	}

	userIdStr := fmt.Sprintf("%v", user.ID)
	storageDir, err := utils.SecureJoin(avatarRootAbs, userIdStr)
	if err != nil {
		log.Printf("RemoveUserAvatar storage dir secure join error: %v\n", err)
		return errors.New("系统错误: 非法头像目录")
	}
	oldAvatarPath, err := utils.SecureJoin(storageDir, user.Avatar)
	if err != nil {
		log.Printf("RemoveUserAvatar file secure join error: %v\n", err)
		return errors.New("系统错误: 非法头像文件路径")
	}

	// 更新数据库
	if err := db.DB.Model(user).Select("Avatar").Updates(map[string]interface{}{"avatar": ""}).Error; err != nil {
		log.Printf("DB Remove avatar error: %v\n", err)
		return errors.New("系统错误: 移除头像失败")
	}

	// 删除文件
	if err := os.Remove(oldAvatarPath); err != nil && !os.IsNotExist(err) {
		log.Printf("Remove avatar file error: %v\n", err)
	}

	return nil
}
