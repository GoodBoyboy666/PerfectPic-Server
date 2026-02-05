package utils

import (
	"io"
	"net/http"
	"regexp"
	"strings"
)

// ValidateUsername checks if the username meets the requirements.
func ValidateUsername(username string) (bool, string) {
	if len(username) < 4 || len(username) > 20 {
		return false, "用户名长度必须在4到20个字符之间"
	}

	// 允许英文大小写、数字和下划线
	// 严格控制字符集
	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9_]+$`, username); !matched {
		return false, "用户名只能包含英文大小写、数字和下划线"
	}

	// 检查保留用户名，防止冒充官方
	reserved := []string{"admin", "root", "system", "audit", "security", "support"}
	for _, r := range reserved {
		if strings.EqualFold(username, r) {
			return false, "用户名包含保留词汇，不可使用"
		}
	}

	// 不能是纯数字
	if matched, _ := regexp.MatchString(`^[0-9]+$`, username); matched {
		return false, "用户名不能为纯数字"
	}

	return true, ""
}

// ValidatePassword checks if the password meets the requirements.
// Returns true if valid, otherwise false and an error message.
func ValidatePassword(password string) (bool, string) {
	if len(password) < 8 {
		return false, "密码最少8位"
	}

	if matched, _ := regexp.MatchString(`^[a-zA-Z0-9[:punct:]]+$`, password); !matched {
		return false, "密码只能包含英文大小写、数字和符号"
	}

	hasLetter, _ := regexp.MatchString(`[a-zA-Z]`, password)
	hasNum, _ := regexp.MatchString(`[0-9]`, password)
	if !hasLetter || !hasNum {
		return false, "密码必须包含至少一个字母和一个数字"
	}

	return true, ""
}

// ValidateEmail checks if the email is valid.
func ValidateEmail(email string) (bool, string) {
	// 简单的邮箱正则验证
	regex := `^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$`
	matched, _ := regexp.MatchString(regex, email)
	if !matched {
		return false, "邮箱格式不正确"
	}
	return true, ""
}

// ValidateImageContent checks if the file content matches the extension.
func ValidateImageContent(reader io.ReadSeeker, ext string) (bool, string) {
	buffer := make([]byte, 512)
	_, err := reader.Read(buffer)
	if err != nil && err != io.EOF {
		return false, "读取文件内容失败"
	}

	// 重置读取位置
	if _, err := reader.Seek(0, 0); err != nil {
		return false, "重置文件读取位置失败"
	}

	contentType := http.DetectContentType(buffer)

	allowedTypes := map[string]map[string]bool{
		"image/jpeg":     {".jpg": true, ".jpeg": true},
		"image/png":      {".png": true},
		"image/gif":      {".gif": true},
		"image/webp":     {".webp": true},
		"image/bmp":      {".bmp": true},
		"image/x-ms-bmp": {".bmp": true},
	}

	if exts, ok := allowedTypes[contentType]; ok {
		if exts[ext] {
			return true, ""
		}
	}

	return false, "文件真实类型(" + contentType + ")与扩展名(" + ext + ")不匹配或不支持"
}
