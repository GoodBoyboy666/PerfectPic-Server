package service

import (
	"testing"
	"time"

	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/utils"

	"golang.org/x/crypto/bcrypt"
)

func TestLoginUser_Success(t *testing.T) {
	setupTestDB(t)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{
		Username:      "alice",
		Password:      string(hashed),
		Admin:         true,
		Status:        1,
		Email:         "alice@example.com",
		EmailVerified: true,
	}
	if err := db.DB.Create(&u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	token, err := LoginUser("alice", "abc12345")
	if err != nil {
		t.Fatalf("LoginUser error: %v", err)
	}
	claims, err := utils.ParseLoginToken(token)
	if err != nil {
		t.Fatalf("ParseLoginToken error: %v", err)
	}
	if claims.ID != u.ID || claims.Username != "alice" || !claims.Admin {
		t.Fatalf("unexpected claims: %+v", claims)
	}
}

func TestLoginUser_WrongPasswordUnauthorized(t *testing.T) {
	setupTestDB(t)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{
		Username: "alice",
		Password: string(hashed),
		Status:   1,
	}
	_ = db.DB.Create(&u).Error

	_, err := LoginUser("alice", "wrongpass1")
	if err == nil {
		t.Fatalf("expected error")
	}
	authErr, ok := AsAuthError(err)
	if !ok || authErr.Code != AuthErrorUnauthorized {
		t.Fatalf("expected unauthorized auth error, got: %#v (%v)", authErr, err)
	}
}

func TestLoginUser_BlockedUnverifiedForbidden(t *testing.T) {
	setupTestDB(t)

	// Enable block-unverified.
	if err := db.DB.Save(&model.Setting{Key: consts.ConfigBlockUnverifiedUsers, Value: "true"}).Error; err != nil {
		t.Fatalf("set setting: %v", err)
	}
	ClearCache()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{
		Username:      "alice",
		Password:      string(hashed),
		Status:        1,
		Email:         "alice@example.com",
		EmailVerified: false,
	}
	if err := db.DB.Create(&u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	_, err := LoginUser("alice", "abc12345")
	if err == nil {
		t.Fatalf("expected error")
	}
	authErr, ok := AsAuthError(err)
	if !ok || authErr.Code != AuthErrorForbidden {
		t.Fatalf("expected forbidden auth error, got: %#v (%v)", authErr, err)
	}
}

func TestRegisterUser_ValidationError(t *testing.T) {
	setupTestDB(t)

	err := RegisterUser("ab", "short", "bad-email")
	if err == nil {
		t.Fatalf("expected error")
	}
	authErr, ok := AsAuthError(err)
	if !ok || authErr.Code != AuthErrorValidation {
		t.Fatalf("expected validation auth error, got: %#v (%v)", authErr, err)
	}
}

func TestRegisterUser_DuplicateUsernameConflict(t *testing.T) {
	setupTestDB(t)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "a1@example.com"}
	if err := db.DB.Create(&u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	err := RegisterUser("alice", "abc12345", "alice2@example.com")
	if err == nil {
		t.Fatalf("expected error")
	}
	authErr, ok := AsAuthError(err)
	if !ok || authErr.Code != AuthErrorConflict {
		t.Fatalf("expected conflict auth error, got: %#v (%v)", authErr, err)
	}
}

func TestVerifyEmail_SetsVerified(t *testing.T) {
	setupTestDB(t)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "alice@example.com", EmailVerified: false}
	if err := db.DB.Create(&u).Error; err != nil {
		t.Fatalf("create user: %v", err)
	}

	token, err := utils.GenerateEmailToken(u.ID, u.Email, 1*time.Hour)
	if err != nil {
		t.Fatalf("GenerateEmailToken: %v", err)
	}

	already, err := VerifyEmail(token)
	if err != nil {
		t.Fatalf("VerifyEmail error: %v", err)
	}
	if already {
		t.Fatalf("expected alreadyVerified=false on first verify")
	}

	var got model.User
	if err := db.DB.First(&got, u.ID).Error; err != nil {
		t.Fatalf("load user: %v", err)
	}
	if !got.EmailVerified {
		t.Fatalf("expected user to be verified")
	}

	already2, err := VerifyEmail(token)
	if err != nil {
		t.Fatalf("VerifyEmail second call error: %v", err)
	}
	if !already2 {
		t.Fatalf("expected alreadyVerified=true on second verify")
	}
}

func TestRegisterUser_SuccessCreatesUser(t *testing.T) {
	setupTestDB(t)

	if err := RegisterUser("alice_1", "abc12345", "a1@example.com"); err != nil {
		t.Fatalf("RegisterUser: %v", err)
	}

	var u model.User
	if err := db.DB.Where("username = ?", "alice_1").First(&u).Error; err != nil {
		t.Fatalf("expected user created: %v", err)
	}
	if u.EmailVerified {
		t.Fatalf("expected email_verified false by default")
	}
	if bcrypt.CompareHashAndPassword([]byte(u.Password), []byte("abc12345")) != nil {
		t.Fatalf("expected stored password to be bcrypt hash")
	}
}

func TestAuthError_ErrorString(t *testing.T) {
	e := &AuthError{Code: AuthErrorUnauthorized, Message: "x"}
	if e.Error() != "x" {
		t.Fatalf("unexpected error string: %q", e.Error())
	}
}

func TestVerifyEmailChange_UpdatesEmail(t *testing.T) {
	setupTestDB(t)

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "a@example.com", EmailVerified: true}
	_ = db.DB.Create(&u).Error

	token, err := utils.GenerateEmailChangeToken(u.ID, "a@example.com", "new@example.com", time.Hour)
	if err != nil {
		t.Fatalf("GenerateEmailChangeToken: %v", err)
	}

	if err := VerifyEmailChange(token); err != nil {
		t.Fatalf("VerifyEmailChange: %v", err)
	}

	var got model.User
	_ = db.DB.First(&got, u.ID).Error
	if got.Email != "new@example.com" || !got.EmailVerified {
		t.Fatalf("unexpected user email after change: %+v", got)
	}
}

func TestResetPassword_Flow(t *testing.T) {
	setupTestDB(t)
	resetPasswordResetStore()

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "a@example.com", EmailVerified: false}
	_ = db.DB.Create(&u).Error

	token, err := GenerateForgetPasswordToken(u.ID)
	if err != nil {
		t.Fatalf("GenerateForgetPasswordToken: %v", err)
	}

	// invalid new password
	err = ResetPassword(token, "short")
	if err == nil {
		t.Fatalf("expected error for invalid new password")
	}

	// generate again due to one-time use token deletion behavior
	token, _ = GenerateForgetPasswordToken(u.ID)
	if err := ResetPassword(token, "abc123456"); err != nil {
		t.Fatalf("ResetPassword: %v", err)
	}

	var got model.User
	_ = db.DB.First(&got, u.ID).Error
	if bcrypt.CompareHashAndPassword([]byte(got.Password), []byte("abc123456")) != nil {
		t.Fatalf("expected password updated")
	}
	if !got.EmailVerified {
		t.Fatalf("expected email_verified set true on reset")
	}
}

func TestRequestPasswordReset_Behavior(t *testing.T) {
	setupTestDB(t)
	resetPasswordResetStore()

	// Unknown email should be nil (no user enumeration).
	if err := RequestPasswordReset("unknown@example.com"); err != nil {
		t.Fatalf("expected nil for unknown email, got %v", err)
	}

	hashed, _ := bcrypt.GenerateFromPassword([]byte("abc12345"), bcrypt.DefaultCost)
	u := model.User{Username: "alice", Password: string(hashed), Status: 1, Email: "a@example.com", EmailVerified: true}
	_ = db.DB.Create(&u).Error

	if err := RequestPasswordReset("a@example.com"); err != nil {
		t.Fatalf("RequestPasswordReset: %v", err)
	}

	b := model.User{Username: "banned", Password: string(hashed), Status: 2, Email: "b@example.com"}
	_ = db.DB.Create(&b).Error
	err := RequestPasswordReset("b@example.com")
	if err == nil {
		t.Fatalf("expected forbidden error")
	}
	if ae, ok := AsAuthError(err); !ok || ae.Code != AuthErrorForbidden {
		t.Fatalf("expected forbidden AuthError, got %v", err)
	}
}
