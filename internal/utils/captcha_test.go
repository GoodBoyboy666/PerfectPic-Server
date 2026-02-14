package utils

import "testing"

// 测试内容：验证验证码生成、正确校验、一次性失效及错误答案失败。
func TestCaptcha_GenerateAndVerify(t *testing.T) {
	id, b64, answer, err := MakeCaptcha()
	if err != nil {
		t.Fatalf("MakeCaptcha 错误: %v", err)
	}
	if id == "" || b64 == "" || answer == "" {
		t.Fatalf("期望 non-empty captcha fields, id=%q b64=%q answer=%q", id, b64, answer)
	}

	if ok := VerifyCaptcha(id, answer); !ok {
		t.Fatalf("期望 captcha verify to succeed for correct answer")
	}

	// 由于 VerifyCaptcha 包装里 clear=true，验证码为一次性。
	if ok := VerifyCaptcha(id, answer); ok {
		t.Fatalf("期望 captcha verify to fail after being cleared")
	}

	id2, _, _, err := MakeCaptcha()
	if err != nil {
		t.Fatalf("MakeCaptcha(2) 错误: %v", err)
	}
	if ok := VerifyCaptcha(id2, "wrong"); ok {
		t.Fatalf("期望 captcha verify to fail for wrong answer")
	}
}
