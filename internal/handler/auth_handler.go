package handler

import (
	"fmt"
	"net/http"
	"perfect-pic-server/internal/config"
	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/service"
	"perfect-pic-server/internal/utils"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

func Login(c *gin.Context) {
	cfg := config.Get()
	var req struct {
		Username      string `json:"username" binding:"required"`
		Password      string `json:"password" binding:"required"`
		CaptchaID     string `json:"captcha_id" binding:"required"`
		CaptchaAnswer string `json:"captcha_answer" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数错误"})
		return
	}

	if !utils.VerifyCaptcha(req.CaptchaID, req.CaptchaAnswer) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "验证码错误或已过期"})
		return
	}

	var user model.User
	result := db.DB.Where("username = ?", req.Username).First(&user)
	if result.Error != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "用户名或密码错误"})
		return
	}

	if user.Status == 2 {
		c.JSON(http.StatusForbidden, gin.H{"error": "该账号已被封禁"})
		return
	}
	if user.Status == 3 {
		c.JSON(http.StatusForbidden, gin.H{"error": "该账号已停用"})
		return
	}

	// 检查是否阻止未验证邮箱用户登录
	if service.GetBool(consts.ConfigBlockUnverifiedUsers) {
		if user.Email != "" && !user.EmailVerified {
			c.JSON(http.StatusForbidden, gin.H{"error": "请先验证邮箱后再登录"})
			return
		}
	}

	// 签发 Token
	token, _ := utils.GenerateLoginToken(user.ID, user.Username, user.Admin, time.Hour*time.Duration(cfg.JWT.ExpirationHours))

	c.JSON(http.StatusOK, gin.H{
		"token":   token,
		"message": "登录成功",
	})
}

func Register(c *gin.Context) {
	var req struct {
		Username      string `json:"username" binding:"required"`
		Password      string `json:"password" binding:"required"`
		Email         string `json:"email" binding:"required"`
		CaptchaID     string `json:"captcha_id" binding:"required"`
		CaptchaAnswer string `json:"captcha_answer" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数格式错误"})
		return
	}

	if ok, msg := utils.ValidatePassword(req.Password); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	if ok, msg := utils.ValidateUsername(req.Username); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	if ok, msg := utils.ValidateEmail(req.Email); !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": msg})
		return
	}

	if !utils.VerifyCaptcha(req.CaptchaID, req.CaptchaAnswer) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "验证码错误或已过期"})
		return
	}

	allowRegister := service.GetBool(consts.ConfigAllowRegister)
	if !allowRegister {
		c.JSON(http.StatusForbidden, gin.H{"error": "注册功能已关闭"})
		return
	}

	var existingUser model.User
	result := db.DB.Where("username = ?", req.Username).First(&existingUser)
	if result.RowsAffected > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "用户名已存在"})
		return
	}

	var existingEmailUser model.User
	if db.DB.Where("email = ?", req.Email).First(&existingEmailUser).RowsAffected > 0 {
		c.JSON(http.StatusConflict, gin.H{"error": "邮箱已被注册"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "密码加密失败"})
		return
	}

	newUser := model.User{
		Username:      req.Username,
		Password:      string(hashedPassword),
		Email:         req.Email,
		EmailVerified: false,
		Admin:         false,
		Avatar:        "", // 默认头像
	}

	if err := db.DB.Create(&newUser).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "注册失败，请稍后重试"})
		return
	}

	// 生成验证 Token (有效期30分钟)
	verifyToken, _ := utils.GenerateEmailToken(newUser.ID, newUser.Email, 30*time.Minute)

	baseURL := service.GetString(consts.ConfigBaseURL)
	if baseURL == "" {
		baseURL = "http://localhost"
	}
	// 去除末尾斜杠
	if len(baseURL) > 0 && baseURL[len(baseURL)-1] == '/' {
		baseURL = baseURL[:len(baseURL)-1]
	}

	// 生成前端验证页面的链接
	// 用户点击邮件中的链接 -> 跳转到前端 /auth/email-verify 页面 -> 前端获取 token 并调用后端 /api/auth/email-verify 接口
	verifyUrl := fmt.Sprintf("%s/auth/email-verify?token=%s", baseURL, verifyToken)

	// 异步发送验证邮件
	go func() {
		_ = service.SendVerificationEmail(newUser.Email, newUser.Username, verifyUrl)
	}()

	c.JSON(http.StatusOK, gin.H{"message": "注册成功，请前往邮箱验证"})
}

func EmailVerify(c *gin.Context) {
	tokenString := c.Query("token")
	if tokenString == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "无效的验证链接"})
		return
	}

	claims, err := utils.ParseEmailToken(tokenString)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "验证链接已失效或不正确"})
		return
	}

	var user model.User
	if err := db.DB.First(&user, claims.ID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "用户不存在"})
		return
	}

	// 验证 Token 中的邮箱是否与当前用户邮箱一致
	if user.Email != claims.Email {
		c.JSON(http.StatusBadRequest, gin.H{"error": "邮箱不匹配，请重新发起验证"})
		return
	}

	if user.EmailVerified {
		c.JSON(http.StatusOK, gin.H{"message": "邮箱已验证，无需重复验证"})
		return
	}

	user.EmailVerified = true
	if err := db.DB.Save(&user).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "验证失败，请稍后重试"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "邮箱验证成功，现在可以登录了"})
}

func GetRegisterState(c *gin.Context) {
	allowRegister := service.GetBool(consts.ConfigAllowRegister)
	c.JSON(http.StatusOK, gin.H{
		"allow_register": allowRegister,
	})
}
