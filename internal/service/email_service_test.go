package service

import (
	"strings"
	"testing"

	"perfect-pic-server/internal/config"
	"perfect-pic-server/internal/consts"
	"perfect-pic-server/internal/db"
	"perfect-pic-server/internal/model"
)

// 测试内容：验证邮件模板渲染能正确替换变量。
func TestRenderTemplate(t *testing.T) {
	out, err := renderTemplate("hi {{.Name}}", map[string]string{"Name": "alice"})
	if err != nil {
		t.Fatalf("renderTemplate: %v", err)
	}
	if out != "hi alice" {
		t.Fatalf("非预期输出: %q", out)
	}
}

// 测试内容：验证邮箱地址头格式化与非法地址校验。
func TestFormatAddressHeader(t *testing.T) {
	header, addr, err := formatAddressHeader("Alice <alice@example.com>")
	if err != nil {
		t.Fatalf("formatAddressHeader: %v", err)
	}
	if addr != "alice@example.com" {
		t.Fatalf("非预期地址: %q", addr)
	}
	if !strings.Contains(header, "<alice@example.com>") {
		t.Fatalf("非预期头部: %q", header)
	}
	if strings.ContainsAny(header, "\r\n") {
		t.Fatalf("头部包含 CRLF: %q", header)
	}

	header2, addr2, err := formatAddressHeader("bob@example.com")
	if err != nil {
		t.Fatalf("formatAddressHeader: %v", err)
	}
	if header2 != "bob@example.com" || addr2 != "bob@example.com" {
		t.Fatalf("非预期 header/addr: %q %q", header2, addr2)
	}

	_, _, err = formatAddressHeader("not-an-email")
	if err == nil {
		t.Fatalf("期望无效地址返回错误")
	}
}

// 测试内容：验证邮件消息构建包含必要头部与正文。
func TestBuildEmailMessage(t *testing.T) {
	msg, err := buildEmailMessage("from@example.com", "to@example.com", "主题", "<p>hi</p>")
	if err != nil {
		t.Fatalf("buildEmailMessage: %v", err)
	}
	s := string(msg)
	if !strings.Contains(s, "Subject:") || !strings.Contains(s, "MIME-Version: 1.0") {
		t.Fatalf("邮件内容缺少头部: %q", s)
	}
	if !strings.Contains(s, "<p>hi</p>") {
		t.Fatalf("邮件内容缺少正文")
	}
}

// 测试内容：验证 SMTP 主机缺失时发送测试邮件返回错误。
func TestSendTestEmail_MissingHost(t *testing.T) {
	// TestMain 中的 config.InitConfig 设置了默认值；SMTP host 默认为空。
	err := SendTestEmail("a@example.com")
	if err == nil {
		t.Fatalf("期望返回错误 when SMTP host is 缺少")
	}
}

// 测试内容：验证 SMTP 禁用时发送验证邮件为 no-op。
func TestSendVerificationEmail_SMTPDisabledNoop(t *testing.T) {
	// 默认设置 enable_smtp=false，因此这里应为 no-op。
	if err := SendVerificationEmail("a@example.com", "alice", "http://example/verify"); err != nil {
		t.Fatalf("期望为 nil，实际为 %v", err)
	}
}

// 测试内容：验证 SMTP 禁用时发送邮箱变更验证为 no-op。
func TestSendEmailChangeVerification_SMTPDisabledNoop(t *testing.T) {
	if err := SendEmailChangeVerification("a@example.com", "alice", "old@example.com", "new@example.com", "http://example/verify"); err != nil {
		t.Fatalf("期望为 nil，实际为 %v", err)
	}
}

// 测试内容：验证 SMTP 禁用时发送密码重置邮件为 no-op。
func TestSendPasswordResetEmail_SMTPDisabledNoop(t *testing.T) {
	if err := SendPasswordResetEmail("a@example.com", "alice", "http://example/reset"); err != nil {
		t.Fatalf("期望为 nil，实际为 %v", err)
	}
}

// 测试内容：验证 SSL 发送在连接失败时返回错误。
func TestSendMailWithSSL_DialFailure(t *testing.T) {
	_, _ = buildEmailMessage("from@example.com", "to@example.com", "sub", "body")
	err := sendMailWithSSL("127.0.0.1:1", nil, "from@example.com", []string{"to@example.com"}, []byte("x"))
	if err == nil {
		t.Fatalf("期望返回错误")
	}
}

// 测试内容：验证启用 SMTP 且主机不可达时各发送函数会快速失败。
func TestEmailSendFunctions_AttemptSendAndFailFast(t *testing.T) {
	setupTestDB(t)

	// 在设置中启用 SMTP。
	_ = db.DB.Save(&model.Setting{Key: consts.ConfigEnableSMTP, Value: "true"}).Error
	ClearCache()

	// 重新初始化配置，使用不可达的 SMTP host/port 以便 SendMail 快速失败。
	cfgDir := t.TempDir()
	t.Setenv("PERFECT_PIC_SERVER_MODE", "debug")
	t.Setenv("PERFECT_PIC_JWT_SECRET", "test_secret")
	t.Setenv("PERFECT_PIC_SMTP_HOST", "127.0.0.1")
	t.Setenv("PERFECT_PIC_SMTP_PORT", "1")
	t.Setenv("PERFECT_PIC_SMTP_FROM", "Perfect Pic <from@example.com>")
	config.InitConfigWithoutWatch(cfgDir)

	if err := SendVerificationEmail("to@example.com", "alice", "http://example/verify"); err == nil {
		t.Fatalf("期望发送失败")
	}
	if err := SendEmailChangeVerification("to@example.com", "alice", "old@example.com", "new@example.com", "http://example/verify"); err == nil {
		t.Fatalf("期望发送失败")
	}
	if err := SendPasswordResetEmail("to@example.com", "alice", "http://example/reset"); err == nil {
		t.Fatalf("期望发送失败")
	}
	if err := SendTestEmail("to@example.com"); err == nil {
		t.Fatalf("期望发送失败")
	}
}
