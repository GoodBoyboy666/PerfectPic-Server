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

func TestGetCaptchaProviderInfo_DefaultIsImage(t *testing.T) {
	setupTestDB(t)
	ClearCache()

	info := GetCaptchaProviderInfo()
	if info.Provider != CaptchaProviderImage {
		t.Fatalf("expected default provider to be image, got %q", info.Provider)
	}
}

func TestGetCaptchaProviderInfo_UnknownFallsBackToImage(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "unknown"}).Error
	ClearCache()

	info := GetCaptchaProviderInfo()
	if info.Provider != CaptchaProviderImage {
		t.Fatalf("expected fallback to image, got %q", info.Provider)
	}
}

func TestGetCaptchaProviderInfo_Disabled(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: ""}).Error
	ClearCache()

	info := GetCaptchaProviderInfo()
	if info.Provider != CaptchaProviderDisabled {
		t.Fatalf("expected disabled provider, got %q", info.Provider)
	}
}

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
			t.Fatalf("expected provider %q, got %q", tc.provider, info.Provider)
		}
		if info.PublicConfig == nil || info.PublicConfig[tc.wantKey] != "pub" {
			t.Fatalf("expected public config %q=pub, got %#v", tc.wantKey, info.PublicConfig)
		}
	}
}

func TestVerifyCaptchaChallenge_DisabledProviderAlwaysOK(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: ""}).Error
	ClearCache()

	ok, msg := VerifyCaptchaChallenge("", "", "", "1.2.3.4")
	if !ok || msg != "" {
		t.Fatalf("expected ok for disabled provider, got ok=%v msg=%q", ok, msg)
	}
}

func TestVerifyCaptchaChallenge_ImageProviderValidates(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "image"}).Error
	ClearCache()

	ok, msg := VerifyCaptchaChallenge("", "", "", "1.2.3.4")
	if ok || msg == "" {
		t.Fatalf("expected failure for empty captcha fields, got ok=%v msg=%q", ok, msg)
	}

	id, _, answer, err := utils.MakeCaptcha()
	if err != nil {
		t.Fatalf("MakeCaptcha: %v", err)
	}

	ok2, msg2 := VerifyCaptchaChallenge(id, answer, "", "1.2.3.4")
	if !ok2 || msg2 != "" {
		t.Fatalf("expected success for valid captcha, got ok=%v msg=%q", ok2, msg2)
	}
}

func TestGetCaptchaProviderInfo_PublicConfig(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "turnstile"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaTurnstileSiteKey, Value: "site"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaTurnstileSecretKey, Value: "secret"}).Error
	ClearCache()

	info := GetCaptchaProviderInfo()
	if info.Provider != CaptchaProviderTurnstile {
		t.Fatalf("expected turnstile, got %q", info.Provider)
	}
	if info.PublicConfig["turnstile_site_key"] != "site" {
		t.Fatalf("expected site key in public config")
	}
}

func TestVerifyCaptchaChallenge_ProviderConfigMissing(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "hcaptcha"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaHcaptchaSiteKey, Value: ""}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaHcaptchaSecretKey, Value: ""}).Error
	ClearCache()

	ok, msg := VerifyCaptchaChallenge("", "", "token", "1.1.1.1")
	if ok || msg == "" {
		t.Fatalf("expected config error, got ok=%v msg=%q", ok, msg)
	}
}

func TestVerifyCaptchaChallenge_GeetestTokenParseErrors(t *testing.T) {
	setupTestDB(t)

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "geetest"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaGeetestCaptchaID, Value: "id"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaGeetestCaptchaKey, Value: "key"}).Error
	ClearCache()

	ok, msg := VerifyCaptchaChallenge("", "", "not-base64", "")
	if ok || msg == "" {
		t.Fatalf("expected format error, got ok=%v msg=%q", ok, msg)
	}

	// base64 ok but missing required fields
	b, _ := json.Marshal(map[string]string{"lot_number": "x"})
	token := base64.StdEncoding.EncodeToString(b)
	ok, msg = VerifyCaptchaChallenge("", "", token, "")
	if ok || msg == "" {
		t.Fatalf("expected incomplete error, got ok=%v msg=%q", ok, msg)
	}
}

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

	// Turnstile: token empty + success + hostname mismatch error path.
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "turnstile"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaTurnstileSiteKey, Value: "site"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaTurnstileSecretKey, Value: "secret"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaTurnstileVerifyURL, Value: srv.URL + "/turnstile"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaTurnstileExpectedHostname, Value: ""}).Error
	ClearCache()

	ok, msg := VerifyCaptchaChallenge("", "", "", "1.1.1.1")
	if ok || msg == "" {
		t.Fatalf("expected token required, got ok=%v msg=%q", ok, msg)
	}
	ok, msg = VerifyCaptchaChallenge("", "", "token", "1.1.1.1")
	if !ok || msg != "" {
		t.Fatalf("expected success, got ok=%v msg=%q", ok, msg)
	}

	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaTurnstileExpectedHostname, Value: "wrong-host"}).Error
	ClearCache()
	ok, msg = VerifyCaptchaChallenge("", "", "token", "1.1.1.1")
	if ok || msg == "" {
		t.Fatalf("expected failure, got ok=%v msg=%q", ok, msg)
	}

	// reCAPTCHA
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "recaptcha"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaRecaptchaSiteKey, Value: "site"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaRecaptchaSecretKey, Value: "secret"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaRecaptchaVerifyURL, Value: srv.URL + "/recaptcha"}).Error
	ClearCache()
	ok, msg = VerifyCaptchaChallenge("", "", "token", "1.1.1.1")
	if !ok || msg != "" {
		t.Fatalf("expected success, got ok=%v msg=%q", ok, msg)
	}

	// hCaptcha
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaProvider, Value: "hcaptcha"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaHcaptchaSiteKey, Value: "site"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaHcaptchaSecretKey, Value: "secret"}).Error
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigCaptchaHcaptchaVerifyURL, Value: srv.URL + "/hcaptcha"}).Error
	ClearCache()
	ok, msg = VerifyCaptchaChallenge("", "", "token", "1.1.1.1")
	if !ok || msg != "" {
		t.Fatalf("expected success, got ok=%v msg=%q", ok, msg)
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
		t.Fatalf("expected success, got ok=%v msg=%q", ok, msg)
	}
}
