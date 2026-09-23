package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net/smtp"
	"strings"
	"time"

	"authkit/internal/config"
)

// SMTPEmailService handles sending emails via standard SMTP credentials
type SMTPEmailService struct {
	cfg     config.EmailConfig
	appName string
}

// NewSMTPService creates an SMTP email provider
func NewSMTPService(cfg config.EmailConfig, appName string) *SMTPEmailService {
	return &SMTPEmailService{
		cfg:     cfg,
		appName: appName,
	}
}

func (s *SMTPEmailService) SendVerificationEmail(ctx context.Context, toEmail, userName, code, verifyURL string) error {
	data := EmailData{
		AppName:    s.appName,
		UserName:   userName,
		Code:       code,
		ActionURL:  verifyURL,
		ExpiryMins: 30,
		Year:       time.Now().Year(),
	}
	html, text, err := RenderVerificationEmail(data)
	if err != nil {
		return err
	}
	subject := fmt.Sprintf("[%s] Verify your email address", s.appName)
	return s.sendMail(toEmail, subject, html, text)
}

func (s *SMTPEmailService) SendPasswordResetEmail(ctx context.Context, toEmail, userName, code, resetURL string) error {
	data := EmailData{
		AppName:    s.appName,
		UserName:   userName,
		Code:       code,
		ActionURL:  resetURL,
		ExpiryMins: 30,
		Year:       time.Now().Year(),
	}
	html, text, err := RenderPasswordResetEmail(data)
	if err != nil {
		return err
	}
	subject := fmt.Sprintf("[%s] Reset your password", s.appName)
	return s.sendMail(toEmail, subject, html, text)
}

func (s *SMTPEmailService) SendWelcomeEmail(ctx context.Context, toEmail, userName string) error {
	data := EmailData{
		AppName:  s.appName,
		UserName: userName,
		Year:     time.Now().Year(),
	}
	html, text, err := RenderWelcomeEmail(data)
	if err != nil {
		return err
	}
	subject := fmt.Sprintf("[%s] Welcome to %s", s.appName, s.appName)
	return s.sendMail(toEmail, subject, html, text)
}

func (s *SMTPEmailService) sendMail(to, subject, htmlBody, textBody string) error {
	smtpHost := s.cfg.SMTP.Host
	smtpPort := s.cfg.SMTP.Port
	if smtpPort <= 0 {
		smtpPort = 587
	}
	addr := fmt.Sprintf("%s:%d", smtpHost, smtpPort)

	fromEmail := s.cfg.FromEmail
	if fromEmail == "" {
		fromEmail = "noreply@authkit.local"
	}
	fromName := s.cfg.FromName
	if fromName == "" {
		fromName = s.appName
	}

	fromHeader := fmt.Sprintf("%s <%s>", mime.QEncoding.Encode("utf-8", fromName), fromEmail)

	boundary := "AuthKit-Email-Boundary-xyz"
	var msg strings.Builder
	msg.WriteString(fmt.Sprintf("From: %s\r\n", fromHeader))
	msg.WriteString(fmt.Sprintf("To: %s\r\n", to))
	msg.WriteString(fmt.Sprintf("Subject: %s\r\n", mime.QEncoding.Encode("utf-8", subject)))
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString(fmt.Sprintf("Content-Type: multipart/alternative; boundary=\"%s\"\r\n\r\n", boundary))

	// Plain text part
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/plain; charset=\"utf-8\"\r\n")
	msg.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
	msg.WriteString(textBody)
	msg.WriteString("\r\n\r\n")

	// HTML part
	msg.WriteString(fmt.Sprintf("--%s\r\n", boundary))
	msg.WriteString("Content-Type: text/html; charset=\"utf-8\"\r\n")
	msg.WriteString("Content-Transfer-Encoding: 7bit\r\n\r\n")
	msg.WriteString(htmlBody)
	msg.WriteString("\r\n\r\n")

	msg.WriteString(fmt.Sprintf("--%s--\r\n", boundary))

	var auth smtp.Auth
	if s.cfg.SMTP.Username != "" {
		auth = smtp.PlainAuth("", s.cfg.SMTP.Username, s.cfg.SMTP.Password, smtpHost)
	}

	// SSL/TLS (port 465) or STARTTLS
	if s.cfg.SMTP.Secure || smtpPort == 465 {
		tlsConfig := &tls.Config{
			ServerName: smtpHost,
		}
		conn, err := tls.Dial("tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to dial SMTP over TLS: %w", err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, smtpHost)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
		defer client.Close()

		if auth != nil {
			if err = client.Auth(auth); err != nil {
				return fmt.Errorf("SMTP auth failed: %w", err)
			}
		}

		if err = client.Mail(fromEmail); err != nil {
			return fmt.Errorf("SMTP MAIL command failed: %w", err)
		}
		if err = client.Rcpt(to); err != nil {
			return fmt.Errorf("SMTP RCPT command failed: %w", err)
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("SMTP DATA command failed: %w", err)
		}
		_, err = w.Write([]byte(msg.String()))
		if err != nil {
			return fmt.Errorf("failed to write email body: %w", err)
		}
		return w.Close()
	}

	// Standard STARTTLS connection
	return smtp.SendMail(addr, auth, fromEmail, []string{to}, []byte(msg.String()))
}
