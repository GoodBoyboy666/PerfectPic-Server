package service

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
	"perfect-pic-server/internal/utils"
)

// 测试内容：验证默认验证码提供方为图片验证码。
func TestGetCaptchaProviderInfo_DefaultIsImage(t *testing.T) {
	setupTestDB(t)
	ClearCache()

	info := GetCaptchaProviderInfo()
	if info.Provider != CaptchaProviderImage {
		t.Fatalf("期望 default provider to be image，实际为 %q", info.Provider)
	}
}

// 测试内容：验证未知提供方会回退为图片验证码。
func TestGetCaptchaProviderInfo_UnknownFallsBackToImage(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "unknown"}).Error
	ClearCache()

	info := GetCaptchaProviderInfo()
	if info.Provider != CaptchaProviderImage {
		t.Fatalf("期望 fallback to image，实际为 %q", info.Provider)
	}
}

// 测试内容：验证提供方禁用时返回禁用状态。
func TestGetCaptchaProviderInfo_Disabled(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: ""}).Error
	ClearCache()

	info := GetCaptchaProviderInfo()
	if info.Provider != CaptchaProviderDisabled {
		t.Fatalf("期望 disabled provider，实际为 %q", info.Provider)
	}
}

// 测试内容：验证不同提供方会暴露对应的公共配置键。
func TestGetCaptchaProviderInfo_PublicConfigByProvider(t *testing.T) {
	setupTestDB(t)

	cases := []struct {
		provider string
		key      string
		wantKey  string
	}{
		{provider: CaptchaProviderTurnstile, key: consts.ConfigCaptchaTurnstileSiteKey, wantKey: "turnstile_site_key"},
		{provider: CaptchaProviderRecaptcha, key: consts.ConfigCaptchaRecaptchaSiteKey, wantKey: "recaptcha_site_key"},
		{provider: CaptchaProviderHcaptcha, key: consts.ConfigCaptchaHcaptchaSiteKey, wantKey: "hcaptcha_site_key"},
		{provider: CaptchaProviderGeetest, key: consts.ConfigCaptchaGeetestCaptchaID, wantKey: "geetest_captcha_id"},
	}

	for _, tc := range cases {
		_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: tc.provider}).Error
		_ = db.DB.Save(&model.Setting{Key: tc.key, Value: "pub"}).Error
		ClearCache()

		info := GetCaptchaProviderInfo()
		if info.Provider != tc.provider {
			t.Fatalf("期望 provider %q，实际为 %q", tc.provider, info.Provider)
		}
		if info.PublicConfig == nil || info.PublicConfig[tc.wantKey] != "pub" {
			t.Fatalf("期望 public config %q=pub，实际为 %#v", tc.wantKey, info.PublicConfig)
		}
	}
}

// 测试内容：验证禁用提供方时验证码校验始终通过。
func TestVerifyCaptchaChallenge_DisabledProviderAlwaysOK(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: ""}).Error
	ClearCache()

	ok, msg := VerifyCaptchaChallenge("", "", "", "1.2.3.4")
	if !ok || msg != "" {
		t.Fatalf("期望 ok for disabled provider，实际为 ok=%v msg=%q", ok, msg)
	}
}

// 测试内容：验证图片验证码提供方在空字段失败、正确答案通过。
func TestVerifyCaptchaChallenge_ImageProviderValidates(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "image"}).Error
	ClearCache()

	ok, msg := VerifyCaptchaChallenge("", "", "", "1.2.3.4")
	if ok || msg == "" {
		t.Fatalf("期望 failure for empty captcha fields，实际为 ok=%v msg=%q", ok, msg)
	}

	id, _, answer, err := utils.MakeCaptcha()
	if err != nil {
		t.Fatalf("MakeCaptcha: %v", err)
	}

	ok2, msg2 := VerifyCaptchaChallenge(id, answer, "", "1.2.3.4")
	if !ok2 || msg2 != "" {
		t.Fatalf("期望 success for valid captcha，实际为 ok=%v msg=%q", ok2, msg2)
	}
}

// 测试内容：验证 Turnstile 公共配置可正确读取。
func TestGetCaptchaProviderInfo_PublicConfig(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "turnstile"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaTurnstileSiteKey, Value: "site"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaTurnstileSecretKey, Value: "secret"}).Error
	ClearCache()

	info := GetCaptchaProviderInfo()
	if info.Provider != CaptchaProviderTurnstile {
		t.Fatalf("期望 turnstile，实际为 %q", info.Provider)
	}
	if info.PublicConfig["turnstile_site_key"] != "site" {
		t.Fatalf("期望 site key in public config")
	}
}

// 测试内容：验证提供方配置缺失时校验失败并返回错误信息。
func TestVerifyCaptchaChallenge_ProviderConfigMissing(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "hcaptcha"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaHcaptchaSiteKey, Value: ""}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaHcaptchaSecretKey, Value: ""}).Error
	ClearCache()

	ok, msg := VerifyCaptchaChallenge("", "", "token", "1.1.1.1")
	if ok || msg == "" {
		t.Fatalf("期望 config 错误，实际为 ok=%v msg=%q", ok, msg)
	}
}

// 测试内容：验证 GeeTest token 解析错误与字段缺失的失败路径。
func TestVerifyCaptchaChallenge_GeetestTokenParseErrors(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "geetest"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaGeetestCaptchaID, Value: "id"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaGeetestCaptchaKey, Value: "key"}).Error
	ClearCache()

	ok, msg := VerifyCaptchaChallenge("", "", "not-base64", "")
	if ok || msg == "" {
		t.Fatalf("期望 format 错误，实际为 ok=%v msg=%q", ok, msg)
	}

	// base64 正常但缺少必填字段
	b, _ := json.Marshal(map[string]string{"lot_number": "x"})
	token := base64.StdEncoding.EncodeToString(b)
	ok, msg = VerifyCaptchaChallenge("", "", token, "")
	if ok || msg == "" {
		t.Fatalf("期望 incomplete 错误，实际为 ok=%v msg=%q", ok, msg)
	}
}

// 测试内容：通过测试服务器验证 Turnstile/reCAPTCHA/hCaptcha/GeeTest 的远程校验流程与分支。
func TestVerifyCaptchaChallenge_RemoteProvidersViaTestServer(t *testing.T) {
	setupTestDB(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/turnstile":
			_ = json.NewEncoder(w).Encode(turnstileVerifyResponse{Success: true, Hostname: "example.com"})
		case "/recaptcha":
			_ = json.NewEncoder(w).Encode(recaptchaVerifyResponse{Success: true, Hostname: "example.com"})
		case "/hcaptcha":
			_ = json.NewEncoder(w).Encode(hcaptchaVerifyResponse{Success: true, Hostname: "example.com"})
		case "/geetest":
			_ = json.NewEncoder(w).Encode(geetestVerifyResponse{Result: "success"})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	oldClient := captchaHTTPClient
	captchaHTTPClient = srv.Client()
	defer func() { captchaHTTPClient = oldClient }()

	// Turnstile：token 为空 + 成功响应 + hostname 不匹配的错误路径。
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "turnstile"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaTurnstileSiteKey, Value: "site"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaTurnstileSecretKey, Value: "secret"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaTurnstileVerifyURL, Value: srv.URL + "/turnstile"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaTurnstileExpectedHostname, Value: ""}).Error
	ClearCache()

	ok, msg := VerifyCaptchaChallenge("", "", "", "1.1.1.1")
	if ok || msg == "" {
		t.Fatalf("期望得到 token required，实际为 ok=%v msg=%q", ok, msg)
	}
	ok, msg = VerifyCaptchaChallenge("", "", "token", "1.1.1.1")
	if !ok || msg != "" {
		t.Fatalf("期望 success，实际为 ok=%v msg=%q", ok, msg)
	}

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaTurnstileExpectedHostname, Value: "wrong-host"}).Error
	ClearCache()
	ok, msg = VerifyCaptchaChallenge("", "", "token", "1.1.1.1")
	if ok || msg == "" {
		t.Fatalf("期望 failure，实际为 ok=%v msg=%q", ok, msg)
	}

	// reCAPTCHA
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "recaptcha"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaRecaptchaSiteKey, Value: "site"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaRecaptchaSecretKey, Value: "secret"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaRecaptchaVerifyURL, Value: srv.URL + "/recaptcha"}).Error
	ClearCache()
	ok, msg = VerifyCaptchaChallenge("", "", "token", "1.1.1.1")
	if !ok || msg != "" {
		t.Fatalf("期望 success，实际为 ok=%v msg=%q", ok, msg)
	}

	// hCaptcha
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "hcaptcha"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaHcaptchaSiteKey, Value: "site"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaHcaptchaSecretKey, Value: "secret"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaHcaptchaVerifyURL, Value: srv.URL + "/hcaptcha"}).Error
	ClearCache()
	ok, msg = VerifyCaptchaChallenge("", "", "token", "1.1.1.1")
	if !ok || msg != "" {
		t.Fatalf("期望 success，实际为 ok=%v msg=%q", ok, msg)
	}

	// GeeTest
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "geetest"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaGeetestCaptchaID, Value: "id"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaGeetestCaptchaKey, Value: "key"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaGeetestVerifyURL, Value: srv.URL + "/geetest"}).Error
	ClearCache()

	p := geetestVerifyTokenPayload{
		LotNumber:     "lot",
		CaptchaOutput: "out",
		PassToken:     "pass",
		GenTime:       "time",
	}
	payload, _ := json.Marshal(p)
	tok := base64.StdEncoding.EncodeToString(payload)
	ok, msg = VerifyCaptchaChallenge("", "", tok, "")
	if !ok || msg != "" {
		t.Fatalf("期望 success，实际为 ok=%v msg=%q", ok, msg)
	}
}
