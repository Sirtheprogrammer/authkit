package email

import (
	"context"
	"crypto/tls"
	"fmt"
	"mime"
	"net"
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

func (s *SMTPEmailService) SendTestEmail(ctx context.Context, toEmail string) error {
	subject := fmt.Sprintf("[%s] Test Email - Remote SMTP Operational", s.appName)
	html := fmt.Sprintf(`<!DOCTYPE html>
<html>
<body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background-color: #09090b; color: #ffffff; padding: 40px; margin: 0;">
  <div style="max-width: 560px; margin: 0 auto; background: #121215; border: 1px solid #27272a; border-radius: 8px; padding: 32px;">
    <h2 style="margin-top: 0; color: #ffffff;">Remote SMTP Operational</h2>
    <p style="color: #a1a1aa; line-height: 1.6;">Your remote SMTP configuration in AuthKit is verified and working properly.</p>
    <div style="background: #18181b; border: 1px solid #27272a; border-radius: 6px; padding: 14px; margin: 20px 0; font-family: monospace; font-size: 13px; color: #e4e4e7;">
      Host: %s<br/>
      Port: %d<br/>
      Sender: %s<br/>
      Timestamp: %s
    </div>
    <p style="color: #71717a; font-size: 12px; margin-bottom: 0;">Sent by %s Admin Console.</p>
  </div>
</body>
</html>`, s.cfg.SMTP.Host, s.cfg.SMTP.Port, s.cfg.FromEmail, time.Now().UTC().Format(time.RFC1123), s.appName)

	text := fmt.Sprintf("Remote SMTP Operational\n\nYour remote SMTP configuration in AuthKit is verified and working properly.\nHost: %s:%d\nSender: %s\nTimestamp: %s\n", s.cfg.SMTP.Host, s.cfg.SMTP.Port, s.cfg.FromEmail, time.Now().UTC().Format(time.RFC1123))

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

	dialer := &net.Dialer{Timeout: 10 * time.Second}

	// SSL/TLS Direct connection (e.g. port 465)
	if s.cfg.SMTP.Secure || smtpPort == 465 {
		tlsConfig := &tls.Config{
			ServerName: smtpHost,
		}
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			return fmt.Errorf("failed to dial remote SMTP server over TLS (%s): %w", addr, err)
		}
		defer conn.Close()

		client, err := smtp.NewClient(conn, smtpHost)
		if err != nil {
			return fmt.Errorf("failed to create SMTP client: %w", err)
		}
		defer client.Close()

		if auth != nil {
			if err = client.Auth(auth); err != nil {
				return fmt.Errorf("remote SMTP authentication failed for user '%s': %w", s.cfg.SMTP.Username, err)
			}
		}

		if err = client.Mail(fromEmail); err != nil {
			return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
		}
		if err = client.Rcpt(to); err != nil {
			return fmt.Errorf("SMTP RCPT TO failed: %w", err)
		}

		w, err := client.Data()
		if err != nil {
			return fmt.Errorf("SMTP DATA command failed: %w", err)
		}
		if _, err = w.Write([]byte(msg.String())); err != nil {
			return fmt.Errorf("failed to write email body: %w", err)
		}
		return w.Close()
	}

	// Standard STARTTLS connection (e.g. port 587, 25, 2525)
	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to connect to remote SMTP server (%s): %w", addr, err)
	}
	defer conn.Close()

	client, err := smtp.NewClient(conn, smtpHost)
	if err != nil {
		return fmt.Errorf("failed to initialize SMTP client: %w", err)
	}
	defer client.Close()

	if hasStartTLS, _ := client.Extension("STARTTLS"); hasStartTLS {
		tlsConfig := &tls.Config{
			ServerName: smtpHost,
		}
		if err = client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("failed to negotiate STARTTLS with remote server %s: %w", smtpHost, err)
		}
	}

	if auth != nil {
		if hasAuth, _ := client.Extension("AUTH"); hasAuth {
			if err = client.Auth(auth); err != nil {
				return fmt.Errorf("remote SMTP authentication failed for user '%s': %w", s.cfg.SMTP.Username, err)
			}
		}
	}

	if err = client.Mail(fromEmail); err != nil {
		return fmt.Errorf("SMTP MAIL FROM failed: %w", err)
	}
	if err = client.Rcpt(to); err != nil {
		return fmt.Errorf("SMTP RCPT TO failed: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("SMTP DATA command failed: %w", err)
	}
	if _, err = w.Write([]byte(msg.String())); err != nil {
		return fmt.Errorf("failed to write email body: %w", err)
	}
	return w.Close()
}
