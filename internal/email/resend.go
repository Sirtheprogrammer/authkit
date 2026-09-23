package email

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"authkit/internal/config"
)

// ResendEmailService handles sending emails via the Resend REST API
type ResendEmailService struct {
	cfg        config.EmailConfig
	appName    string
	httpClient *http.Client
}

type resendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
	Text    string   `json:"text,omitempty"`
}

type resendResponse struct {
	ID      string `json:"id"`
	Message string `json:"message,omitempty"`
}

// NewResendService creates a new Resend email provider
func NewResendService(cfg config.EmailConfig, appName string) *ResendEmailService {
	return &ResendEmailService{
		cfg:     cfg,
		appName: appName,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (r *ResendEmailService) SendVerificationEmail(ctx context.Context, toEmail, userName, code, verifyURL string) error {
	data := EmailData{
		AppName:    r.appName,
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
	subject := fmt.Sprintf("[%s] Verify your email address", r.appName)
	return r.send(ctx, toEmail, subject, html, text)
}

func (r *ResendEmailService) SendPasswordResetEmail(ctx context.Context, toEmail, userName, code, resetURL string) error {
	data := EmailData{
		AppName:    r.appName,
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
	subject := fmt.Sprintf("[%s] Reset your password", r.appName)
	return r.send(ctx, toEmail, subject, html, text)
}

func (r *ResendEmailService) SendWelcomeEmail(ctx context.Context, toEmail, userName string) error {
	data := EmailData{
		AppName:  r.appName,
		UserName: userName,
		Year:     time.Now().Year(),
	}
	html, text, err := RenderWelcomeEmail(data)
	if err != nil {
		return err
	}
	subject := fmt.Sprintf("[%s] Welcome to %s", r.appName, r.appName)
	return r.send(ctx, toEmail, subject, html, text)
}

func (r *ResendEmailService) send(ctx context.Context, to, subject, htmlBody, textBody string) error {
	fromEmail := r.cfg.FromEmail
	if fromEmail == "" {
		fromEmail = "onboarding@resend.dev"
	}
	fromName := r.cfg.FromName
	if fromName == "" {
		fromName = r.appName
	}
	formattedFrom := fmt.Sprintf("%s <%s>", fromName, fromEmail)

	reqPayload := resendRequest{
		From:    formattedFrom,
		To:      []string{to},
		Subject: subject,
		HTML:    htmlBody,
		Text:    textBody,
	}

	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		return fmt.Errorf("failed to marshal resend payload: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.resend.com/emails", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("failed to create resend request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+r.cfg.Resend.APIKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := r.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("resend api request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("resend API returned error (status %d): %s", resp.StatusCode, string(body))
	}

	return nil
}
