package utils

import (
	"errors"
	"fmt"
	"perfect-pic-server/internal/config"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

//var jwtSecret = []byte(config.Get().JWT.Secret)

// LoginClaims 用于登录认证（单管理员模式）
type LoginClaims struct {
	ID       uint   `json:"id"`
	Username string `json:"username"`
	Admin    bool   `json:"admin"`
	Type     string `json:"type"` // "login"
	jwt.RegisteredClaims
}

// EmailClaims 用于邮箱验证
type EmailClaims struct {
	ID    uint   `json:"id"`
	Email string `json:"email"`
	Type  string `json:"type"` // "email_verify"
	jwt.RegisteredClaims
}

func getSecret() []byte {
	return []byte(config.Get().JWT.Secret)
}

func GenerateLoginToken(id uint, username string, admin bool, duration time.Duration) (string, error) {
	claims := LoginClaims{
		ID:       id,
		Username: username,
		Admin:    admin,
		Type:     "login",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			Issuer:    "perfect-pic-server",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(getSecret())
}

func GenerateEmailToken(id uint, email string, duration time.Duration) (string, error) {
	claims := EmailClaims{
		ID:    id,
		Email: email,
		Type:  "email_verify",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(duration)),
			Issuer:    "perfect-pic-server",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(getSecret())
}

func ParseLoginToken(tokenString string) (*LoginClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &LoginClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return getSecret(), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*LoginClaims); ok && token.Valid {
		if claims.Type != "login" {
			return nil, errors.New("invalid token type")
		}
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

func ParseEmailToken(tokenString string) (*EmailClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &EmailClaims{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return getSecret(), nil
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := token.Claims.(*EmailClaims); ok && token.Valid {
		if claims.Type != "email_verify" {
			return nil, errors.New("invalid token type")
		}
		return claims, nil
	}

	return nil, errors.New("invalid token")
}
