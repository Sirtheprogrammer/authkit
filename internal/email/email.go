package email

import (
	"context"
	"fmt"
	"log"
	"time"

	"authkit/internal/config"
)

// Service defines email dispatching operations
type Service interface {
	SendVerificationEmail(ctx context.Context, toEmail, userName, code, verifyURL string) error
	SendPasswordResetEmail(ctx context.Context, toEmail, userName, code, resetURL string) error
	SendWelcomeEmail(ctx context.Context, toEmail, userName string) error
}

// NewEmailService instantiates the appropriate email service based on config
func NewEmailService(cfg config.EmailConfig, appName string) (Service, error) {
	if appName == "" {
		appName = "AuthKit"
	}

	switch cfg.Provider {
	case "smtp":
		return NewSMTPService(cfg, appName), nil
	case "resend":
		if cfg.Resend.APIKey == "" {
			return nil, fmt.Errorf("resend email provider configured but API key is missing")
		}
		return NewResendService(cfg, appName), nil
	case "mock", "":
		return NewMockService(cfg, appName), nil
	default:
		return nil, fmt.Errorf("unknown email provider: %s", cfg.Provider)
	}
}

// SentMessage stores captured emails in MockService for inspection and testing
type SentMessage struct {
	To        string
	Subject   string
	Code      string
	ActionURL string
	HTML      string
	Text      string
	SentAt    time.Time
}

// MockService logs emails to console and retains in memory for testing/dev
type MockService struct {
	cfg        config.EmailConfig
	appName    string
	Messages   []SentMessage
}

// NewMockService creates a mock email provider
func NewMockService(cfg config.EmailConfig, appName string) *MockService {
	return &MockService{
		cfg:      cfg,
		appName:  appName,
		Messages: make([]SentMessage, 0),
	}
}

func (m *MockService) SendVerificationEmail(ctx context.Context, toEmail, userName, code, verifyURL string) error {
	data := EmailData{
		AppName:    m.appName,
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

	msg := SentMessage{
		To:        toEmail,
		Subject:   fmt.Sprintf("[%s] Verify your email address", m.appName),
		Code:      code,
		ActionURL: verifyURL,
		HTML:      html,
		Text:      text,
		SentAt:    time.Now(),
	}
	m.Messages = append(m.Messages, msg)
	log.Printf("[EMAIL MOCK] Verification email sent to %s | Code: %s | URL: %s", toEmail, code, verifyURL)
	return nil
}

func (m *MockService) SendPasswordResetEmail(ctx context.Context, toEmail, userName, code, resetURL string) error {
	data := EmailData{
		AppName:    m.appName,
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

	msg := SentMessage{
		To:        toEmail,
		Subject:   fmt.Sprintf("[%s] Reset your password", m.appName),
		Code:      code,
		ActionURL: resetURL,
		HTML:      html,
		Text:      text,
		SentAt:    time.Now(),
	}
	m.Messages = append(m.Messages, msg)
	log.Printf("[EMAIL MOCK] Password reset email sent to %s | Code: %s | URL: %s", toEmail, code, resetURL)
	return nil
}

func (m *MockService) SendWelcomeEmail(ctx context.Context, toEmail, userName string) error {
	data := EmailData{
		AppName:  m.appName,
		UserName: userName,
		Year:     time.Now().Year(),
	}
	html, text, err := RenderWelcomeEmail(data)
	if err != nil {
		return err
	}

	msg := SentMessage{
		To:      toEmail,
		Subject: fmt.Sprintf("[%s] Welcome to %s", m.appName, m.appName),
		HTML:    html,
		Text:    text,
		SentAt:  time.Now(),
	}
	m.Messages = append(m.Messages, msg)
	log.Printf("[EMAIL MOCK] Welcome email sent to %s", toEmail)
	return nil
}

// GetLastMessage retrieves the most recently sent message (useful in tests)
func (m *MockService) GetLastMessage() *SentMessage {
	if len(m.Messages) == 0 {
		return nil
	}
	return &m.Messages[len(m.Messages)-1]
}
