package service

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"html/template"
	"log"
	"mime"
	"net/mail"
	"net/smtp"
	"os"
	"path/filepath"
	"perfect-pic-server/internal/config"
	"perfect-pic-server/internal/consts"
	"regexp"
	"strings"
	"time"
)

type VerificationEmailData struct {
	SiteName  string
	Username  string
	VerifyUrl string
}

type TestEmailData struct {
	SiteName string
	Time     string
}

type EmailChangeData struct {
	SiteName  string
	Username  string
	OldEmail  string
	NewEmail  string
	VerifyUrl string
}

type PasswordResetData struct {
	SiteName string
	Username string
	ResetUrl string
}

var strictEmailRegex = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z0-9]+`)

func shouldSendEmail() bool {
	if !GetBool(consts.ConfigEnableSMTP) {
		return false
	}
	cfg := config.Get()
	return strings.TrimSpace(cfg.SMTP.Host) != ""
}

// SendVerificationEmail 发送验证邮件
func SendVerificationEmail(toEmail, username, verifyUrl string) error {
	// 检查是否开启 SMTP
	if !GetBool(consts.ConfigEnableSMTP) {
		return nil
	}

	cfg := config.Get()
	if cfg.SMTP.Host == "" {
		return nil
	}

	auth := smtp.PlainAuth("", cfg.SMTP.Username, cfg.SMTP.Password, cfg.SMTP.Host)

	siteName := GetString(consts.ConfigSiteName)
	if siteName == "" {
		siteName = "Perfect Pic"
	}

	// 邮件主题
	subject := fmt.Sprintf("欢迎注册 %s - 请验证您的邮箱", siteName)

	// 读取模板文件
	templatePath := filepath.Join(config.GetConfigDir(), "verification-mail.html")
	contentBytes, err := os.ReadFile(templatePath)
	var bodyTpl string
	if err != nil {
		// 如果模板读取失败，使用默认简单模板
		bodyTpl = `
			<h1>欢迎加入 {{.SiteName}}</h1>
			<p>请点击链接验证邮箱: <a href="{{.VerifyUrl}}">{{.VerifyUrl}}</a></p>
		`
	} else {
		bodyTpl = string(contentBytes)
	}

	data := VerificationEmailData{
		SiteName:  siteName,
		Username:  username,
		VerifyUrl: verifyUrl,
	}

	body, err := renderTemplate(bodyTpl, data)
	if err != nil {
		return err
	}

	fromHeader, fromAddr, err := formatAddressHeader(cfg.SMTP.From)
	if err != nil {
		return err
	}
	toHeader, toAddr, err := formatAddressHeader(toEmail)
	if err != nil {
		return err
	}

	msg, err := buildEmailMessage(fromHeader, toHeader, subject, body)
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", cfg.SMTP.Host, cfg.SMTP.Port)

	// 如果配置了 SSL (通常是端口 465)，需要使用 tls 连接
	if cfg.SMTP.SSL {
		return sendMailWithSSL(addr, auth, fromAddr, []string{toAddr}, msg)
	}

	// 默认使用 STARTTLS (通常是端口 587 或 25)
	return smtp.SendMail(addr, auth, fromAddr, []string{toAddr}, msg)
}

// SendTestEmail 发送测试邮件
func SendTestEmail(toEmail string) error {
	cfg := config.Get()
	if cfg.SMTP.Host == "" {
		return fmt.Errorf("SMTP Host 未配置")
	}

	auth := smtp.PlainAuth("", cfg.SMTP.Username, cfg.SMTP.Password, cfg.SMTP.Host)

	siteName := GetString(consts.ConfigSiteName)
	if siteName == "" {
		siteName = "Perfect Pic"
	}

	subject := fmt.Sprintf("%s SMTP 测试邮件", siteName)
	bodyTpl := `
<!DOCTYPE html>
<html>
<body>
    <h3>SMTP 配置测试成功</h3>
    <p>这是一封来自 <strong>{{.SiteName}}</strong> 的测试邮件。</p>
    <p>如果您收到此邮件，说明您的 SMTP 服务配置正确。</p>
    <p>时间: {{.Time}}</p>
</body>
</html>
`
	data := TestEmailData{
		SiteName: siteName,
		Time:     time.Now().Format("2006-01-02 15:04:05"),
	}

	body, err := renderTemplate(bodyTpl, data)
	if err != nil {
		return err
	}

	fromHeader, fromAddr, err := formatAddressHeader(cfg.SMTP.From)
	if err != nil {
		return err
	}
	toHeader, toAddr, err := formatAddressHeader(toEmail)
	if err != nil {
		return err
	}

	msg, err := buildEmailMessage(fromHeader, toHeader, subject, body)
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", cfg.SMTP.Host, cfg.SMTP.Port)

	if cfg.SMTP.SSL {
		return sendMailWithSSL(addr, auth, fromAddr, []string{toAddr}, msg)
	}

	return smtp.SendMail(addr, auth, fromAddr, []string{toAddr}, msg)
}

// SendEmailChangeVerification 发送修改邮箱验证邮件
func SendEmailChangeVerification(toEmail, username, oldEmail, newEmail, verifyUrl string) error {
	// 检查是否开启 SMTP
	if !GetBool(consts.ConfigEnableSMTP) {
		return nil
	}

	cfg := config.Get()
	if cfg.SMTP.Host == "" {
		return nil
	}

	auth := smtp.PlainAuth("", cfg.SMTP.Username, cfg.SMTP.Password, cfg.SMTP.Host)

	siteName := GetString(consts.ConfigSiteName)
	if siteName == "" {
		siteName = "Perfect Pic"
	}

	// 邮件主题
	subject := fmt.Sprintf("%s - 请确认修改邮箱", siteName)

	// 读取模板文件
	templatePath := filepath.Join(config.GetConfigDir(), "email-change-mail.html")
	contentBytes, err := os.ReadFile(templatePath)
	var bodyTpl string
	if err != nil {
		bodyTpl = `
			<h1>修改邮箱确认 - {{.SiteName}}</h1>
			<p>您请求将邮箱从 {{.OldEmail}} 修改为 {{.NewEmail}}。</p>
			<p>请点击链接确认: <a href="{{.VerifyUrl}}">{{.VerifyUrl}}</a></p>
		`
	} else {
		bodyTpl = string(contentBytes)
	}

	data := EmailChangeData{
		SiteName:  siteName,
		Username:  username,
		OldEmail:  oldEmail,
		NewEmail:  newEmail,
		VerifyUrl: verifyUrl,
	}

	body, err := renderTemplate(bodyTpl, data)
	if err != nil {
		return err
	}

	fromHeader, fromAddr, err := formatAddressHeader(cfg.SMTP.From)
	if err != nil {
		return err
	}
	toHeader, toAddr, err := formatAddressHeader(toEmail)
	if err != nil {
		return err
	}

	msg, err := buildEmailMessage(fromHeader, toHeader, subject, body)
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", cfg.SMTP.Host, cfg.SMTP.Port)

	if cfg.SMTP.SSL {
		return sendMailWithSSL(addr, auth, fromAddr, []string{toAddr}, msg)
	}

	return smtp.SendMail(addr, auth, fromAddr, []string{toAddr}, msg)
}

// SendPasswordResetEmail 发送重置密码邮件
func SendPasswordResetEmail(toEmail, username, resetUrl string) error {
	// 检查是否开启 SMTP
	if !GetBool(consts.ConfigEnableSMTP) {
		return nil
	}

	cfg := config.Get()
	if cfg.SMTP.Host == "" {
		return nil
	}

	auth := smtp.PlainAuth("", cfg.SMTP.Username, cfg.SMTP.Password, cfg.SMTP.Host)

	siteName := GetString(consts.ConfigSiteName)
	if siteName == "" {
		siteName = "Perfect Pic"
	}

	// 邮件主题
	subject := fmt.Sprintf("%s - 重置密码请求", siteName)

	// 读取模板文件
	templatePath := filepath.Join(config.GetConfigDir(), "reset-password-mail.html")
	contentBytes, err := os.ReadFile(templatePath)
	var bodyTpl string
	if err != nil {
		bodyTpl = `
			<h1>重置密码 - {{.SiteName}}</h1>
			<p>请点击链接重置密码: <a href="{{.ResetUrl}}">{{.ResetUrl}}</a></p>
			<p>有效期15分钟。</p>
		`
	} else {
		bodyTpl = string(contentBytes)
	}

	data := PasswordResetData{
		SiteName: siteName,
		Username: username,
		ResetUrl: resetUrl,
	}

	body, err := renderTemplate(bodyTpl, data)
	if err != nil {
		return err
	}

	fromHeader, fromAddr, err := formatAddressHeader(cfg.SMTP.From)
	if err != nil {
		return err
	}
	toHeader, toAddr, err := formatAddressHeader(toEmail)
	if err != nil {
		return err
	}

	msg, err := buildEmailMessage(fromHeader, toHeader, subject, body)
	if err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", cfg.SMTP.Host, cfg.SMTP.Port)

	if cfg.SMTP.SSL {
		return sendMailWithSSL(addr, auth, fromAddr, []string{toAddr}, msg)
	}

	return smtp.SendMail(addr, auth, fromAddr, []string{toAddr}, msg)
}

// sendMailWithSSL 使用 TLS 直连方式发送邮件（常用于 465 端口）。
func sendMailWithSSL(addr string, auth smtp.Auth, from string, to []string, msg []byte) error {
	cfg := config.Get()
	// log.Printf("[Email] 正在使用 SSL 连接至 %s 发送邮件", addr)

	// 建立 TLS 连接
	tlsConfig := &tls.Config{
		InsecureSkipVerify: false,
		ServerName:         cfg.SMTP.Host,
	}

	// 增加超时控制
	conn, err := tls.Dial("tcp", addr, tlsConfig)
	if err != nil {
		log.Printf("[Email] TLS 连接失败: %v", err)
		return err
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, cfg.SMTP.Host)
	if err != nil {
		log.Printf("[Email] 创建 SMTP 客户端失败: %v", err)
		return err
	}
	defer client.Close()

	// 认证
	if auth != nil {
		if ok, _ := client.Extension("AUTH"); ok {
			if err = client.Auth(auth); err != nil {
				log.Printf("[Email] SMTP认证失败: %v", err)
				return err
			}
		}
	}

	// 发送流程
	if err = client.Mail(from); err != nil {
		log.Printf("[Email] MAIL FROM 命令失败: %v", err)
		return err
	}
	for _, addr := range to {
		if err = client.Rcpt(addr); err != nil {
			// 不记录具体邮箱地址，防止日志泄露敏感信息
			log.Printf("[Email] RCPT TO 命令失败: %v", err)
			return err
		}
	}
	w, err := client.Data()
	if err != nil {
		log.Printf("[Email] DATA 命令失败: %v", err)
		return err
	}
	_, err = w.Write(msg)
	if err != nil {
		log.Printf("[Email] 写入邮件内容失败: %v", err)
		return err
	}
	err = w.Close()
	if err != nil {
		log.Printf("[Email] 关闭 DATA 失败: %v", err)
		return err
	}

	// log.Printf("[Email] 邮件投递成功")
	return client.Quit()
}

//func parseAddressForHeader(input string) (string, string, error) {
//	cleanInput := sanitizeHeaderContent(input)
//
//	addr, err := mail.ParseAddress(cleanInput)
//	if err != nil {
//		return "", "", err
//	}
//
//	headerValue := addr.String()
//	cleanHeaderValue := sanitizeHeaderContent(headerValue)
//
//	return cleanHeaderValue, addr.Address, nil
//}

func buildEmailMessage(fromHeader, toHeader, subject, body string) ([]byte, error) {
	// 对 Subject 进行 MIME 编码，防止中文乱码或被拒收
	encodedSubject := mime.BEncoding.Encode("UTF-8", subject)
	// 添加 Date 头
	dateStr := time.Now().Format(time.RFC1123Z)

	header := fmt.Sprintf("Date: %s\r\nFrom: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n",
		dateStr, fromHeader, toHeader, encodedSubject)
	return []byte(header + body), nil
}

//func rejectCRLF(value string, field string) error {
//	if strings.ContainsAny(value, "\r\n") {
//		return fmt.Errorf("invalid %s header: CRLF not allowed", field)
//	}
//	return nil
//}

//func sanitizeHeaderContent(input string) string {
//	return strings.Map(func(r rune) rune {
//		if r == '\r' || r == '\n' {
//			return -1 // 丢弃字符
//		}
//		return r
//	}, input)
//}

func renderTemplate(tpl string, data interface{}) (string, error) {
	t, err := template.New("email").Parse(tpl)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// formatAddressHeader 规范化邮箱头部地址并返回 header 展示值与裸邮箱地址。
func formatAddressHeader(input string) (string, string, error) {
	// 解析地址 (如果格式不对，这里直接报错，起到 Validation 作用)
	addr, err := mail.ParseAddress(input)
	if err != nil {
		return "", "", err
	}
	cleanAddr := strictEmailRegex.FindString(addr.Address)
	if cleanAddr == "" {
		return "", "", fmt.Errorf("invalid email format detected")
	}

	var finalHeader string
	if addr.Name != "" {
		cleanName := strings.ReplaceAll(addr.Name, "\r", "")
		cleanName = strings.ReplaceAll(cleanName, "\n", "")
		encodedName := mime.BEncoding.Encode("UTF-8", cleanName)
		finalHeader = fmt.Sprintf("%s <%s>", encodedName, cleanAddr)
	} else {
		// 没有名字，只返回清洗后的地址
		finalHeader = cleanAddr
	}

	return finalHeader, cleanAddr, nil
}
