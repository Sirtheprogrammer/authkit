package api

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"time"

	"authkit/internal/config"
	"authkit/internal/domain"
	"authkit/internal/email"
	"authkit/internal/oauth"
	"authkit/internal/service"
	"gopkg.in/yaml.v3"
)

type ConfigHandler struct {
	mu            sync.Mutex
	cfg           *config.Config
	oauthManager  *oauth.Manager
	emailService  *email.DynamicService
	schemaService *service.SchemaService
	configPath    string
}

func NewConfigHandler(
	cfg *config.Config,
	oauthManager *oauth.Manager,
	emailService *email.DynamicService,
	schemaService *service.SchemaService,
	configPath string,
) *ConfigHandler {
	if configPath == "" {
		configPath = "authkit.yaml"
	}
	return &ConfigHandler{
		cfg:           cfg,
		oauthManager:  oauthManager,
		emailService:  emailService,
		schemaService: schemaService,
		configPath:    configPath,
	}
}

// GetConfig returns sanitized system configuration for the admin console
func (h *ConfigHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()

	resp := map[string]interface{}{
		"version": "1.0.0",
		"server": map[string]interface{}{
			"base_url":        h.cfg.Server.BaseURL,
			"environment":     h.cfg.Server.Environment,
			"allowed_origins": h.cfg.Server.AllowedOrigins,
		},
		"jwt": map[string]interface{}{
			"algorithm":                  h.cfg.JWT.Algorithm,
			"access_expiry":              h.cfg.JWT.AccessExpiry.String(),
			"refresh_expiry":             h.cfg.JWT.RefreshExpiry.String(),
			"require_email_verification": h.cfg.JWT.RequireEmailVerification,
		},
		"oauth": map[string]interface{}{
			"github": map[string]interface{}{
				"enabled":      h.cfg.OAuth.GitHub.Enabled,
				"client_id":    h.cfg.OAuth.GitHub.ClientID,
				"has_secret":   h.cfg.OAuth.GitHub.ClientSecret != "",
				"redirect_url": h.cfg.OAuth.GitHub.RedirectURL,
			},
			"google": map[string]interface{}{
				"enabled":      h.cfg.OAuth.Google.Enabled,
				"client_id":    h.cfg.OAuth.Google.ClientID,
				"has_secret":   h.cfg.OAuth.Google.ClientSecret != "",
				"redirect_url": h.cfg.OAuth.Google.RedirectURL,
			},
			"firebase": map[string]interface{}{
				"enabled":             h.cfg.OAuth.Firebase.Enabled,
				"project_id":          h.cfg.OAuth.Firebase.ProjectID,
				"has_service_account": h.cfg.OAuth.Firebase.ServiceAccountJSON != "",
			},
		},
		"email": map[string]interface{}{
			"provider":   h.cfg.Email.Provider,
			"from_email": h.cfg.Email.FromEmail,
			"from_name":  h.cfg.Email.FromName,
			"smtp": map[string]interface{}{
				"host":         h.cfg.Email.SMTP.Host,
				"port":         h.cfg.Email.SMTP.Port,
				"username":     h.cfg.Email.SMTP.Username,
				"has_password": h.cfg.Email.SMTP.Password != "",
				"secure":       h.cfg.Email.SMTP.Secure,
			},
			"resend": map[string]interface{}{
				"has_api_key": h.cfg.Email.Resend.APIKey != "",
			},
		},
		"schema": map[string]interface{}{
			"strict": h.cfg.Schema.Strict,
			"fields": h.cfg.Schema.Fields,
		},
	}

	writeJSONResponse(w, http.StatusOK, resp)
}

type UpdateConfigRequest struct {
	OAuth struct {
		GitHub struct {
			Enabled      *bool   `json:"enabled"`
			ClientID     *string `json:"client_id"`
			ClientSecret *string `json:"client_secret"`
			RedirectURL  *string `json:"redirect_url"`
		} `json:"github"`
		Google struct {
			Enabled      *bool   `json:"enabled"`
			ClientID     *string `json:"client_id"`
			ClientSecret *string `json:"client_secret"`
			RedirectURL  *string `json:"redirect_url"`
		} `json:"google"`
		Firebase struct {
			Enabled            *bool   `json:"enabled"`
			ProjectID          *string `json:"project_id"`
			ServiceAccountJSON *string `json:"service_account_json"`
		} `json:"firebase"`
	} `json:"oauth"`
	Email struct {
		Provider  *string `json:"provider"`
		FromEmail *string `json:"from_email"`
		FromName  *string `json:"from_name"`
		SMTP      struct {
			Host     *string `json:"host"`
			Port     *int    `json:"port"`
			Username *string `json:"username"`
			Password *string `json:"password"`
			Secure   *bool   `json:"secure"`
		} `json:"smtp"`
		Resend struct {
			APIKey *string `json:"api_key"`
		} `json:"resend"`
	} `json:"email"`
	Schema struct {
		Strict *bool                    `json:"strict"`
		Fields []domain.FieldDefinition `json:"fields"`
	} `json:"schema"`
	JWT struct {
		Algorithm                *string `json:"algorithm"`
		AccessExpiry             *string `json:"access_expiry"`
		RefreshExpiry            *string `json:"refresh_expiry"`
		RequireEmailVerification *bool   `json:"require_email_verification"`
	} `json:"jwt"`
}

// UpdateConfig updates system settings, persists to YAML, and hot-reloads runtime services
func (h *ConfigHandler) UpdateConfig(w http.ResponseWriter, r *http.Request) {
	h.mu.Lock()
	defer h.mu.Unlock()

	var req UpdateConfigRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	// 1. Update GitHub OAuth
	if req.OAuth.GitHub.Enabled != nil {
		h.cfg.OAuth.GitHub.Enabled = *req.OAuth.GitHub.Enabled
	}
	if req.OAuth.GitHub.ClientID != nil {
		h.cfg.OAuth.GitHub.ClientID = *req.OAuth.GitHub.ClientID
	}
	if req.OAuth.GitHub.ClientSecret != nil && *req.OAuth.GitHub.ClientSecret != "" && *req.OAuth.GitHub.ClientSecret != "••••••••" {
		h.cfg.OAuth.GitHub.ClientSecret = *req.OAuth.GitHub.ClientSecret
	}
	if req.OAuth.GitHub.RedirectURL != nil {
		h.cfg.OAuth.GitHub.RedirectURL = *req.OAuth.GitHub.RedirectURL
	}

	// 2. Update Google OAuth
	if req.OAuth.Google.Enabled != nil {
		h.cfg.OAuth.Google.Enabled = *req.OAuth.Google.Enabled
	}
	if req.OAuth.Google.ClientID != nil {
		h.cfg.OAuth.Google.ClientID = *req.OAuth.Google.ClientID
	}
	if req.OAuth.Google.ClientSecret != nil && *req.OAuth.Google.ClientSecret != "" && *req.OAuth.Google.ClientSecret != "••••••••" {
		h.cfg.OAuth.Google.ClientSecret = *req.OAuth.Google.ClientSecret
	}
	if req.OAuth.Google.RedirectURL != nil {
		h.cfg.OAuth.Google.RedirectURL = *req.OAuth.Google.RedirectURL
	}

	// 3. Update Firebase Auth
	if req.OAuth.Firebase.Enabled != nil {
		h.cfg.OAuth.Firebase.Enabled = *req.OAuth.Firebase.Enabled
	}
	if req.OAuth.Firebase.ProjectID != nil {
		h.cfg.OAuth.Firebase.ProjectID = *req.OAuth.Firebase.ProjectID
	}
	if req.OAuth.Firebase.ServiceAccountJSON != nil && *req.OAuth.Firebase.ServiceAccountJSON != "" && *req.OAuth.Firebase.ServiceAccountJSON != "••••••••" {
		h.cfg.OAuth.Firebase.ServiceAccountJSON = *req.OAuth.Firebase.ServiceAccountJSON
	}

	// 4. Update Email & Remote SMTP
	if req.Email.Provider != nil {
		h.cfg.Email.Provider = *req.Email.Provider
	}
	if req.Email.FromEmail != nil {
		h.cfg.Email.FromEmail = *req.Email.FromEmail
	}
	if req.Email.FromName != nil {
		h.cfg.Email.FromName = *req.Email.FromName
	}
	if req.Email.SMTP.Host != nil {
		h.cfg.Email.SMTP.Host = *req.Email.SMTP.Host
	}
	if req.Email.SMTP.Port != nil {
		h.cfg.Email.SMTP.Port = *req.Email.SMTP.Port
	}
	if req.Email.SMTP.Username != nil {
		h.cfg.Email.SMTP.Username = *req.Email.SMTP.Username
	}
	if req.Email.SMTP.Password != nil && *req.Email.SMTP.Password != "" && *req.Email.SMTP.Password != "••••••••" {
		h.cfg.Email.SMTP.Password = *req.Email.SMTP.Password
	}
	if req.Email.SMTP.Secure != nil {
		h.cfg.Email.SMTP.Secure = *req.Email.SMTP.Secure
	}
	if req.Email.Resend.APIKey != nil && *req.Email.Resend.APIKey != "" && *req.Email.Resend.APIKey != "••••••••" {
		h.cfg.Email.Resend.APIKey = *req.Email.Resend.APIKey
	}

	// 5. Update Dynamic Schema
	if req.Schema.Strict != nil {
		h.cfg.Schema.Strict = *req.Schema.Strict
	}
	if req.Schema.Fields != nil {
		h.cfg.Schema.Fields = req.Schema.Fields
	}

	// 6. Update JWT
	if req.JWT.Algorithm != nil && (*req.JWT.Algorithm == "RS256" || *req.JWT.Algorithm == "HS256") {
		h.cfg.JWT.Algorithm = *req.JWT.Algorithm
	}
	if req.JWT.AccessExpiry != nil {
		if d, err := time.ParseDuration(*req.JWT.AccessExpiry); err == nil && d > 0 {
			h.cfg.JWT.AccessExpiry = d
		}
	}
	if req.JWT.RefreshExpiry != nil {
		if d, err := time.ParseDuration(*req.JWT.RefreshExpiry); err == nil && d > 0 {
			h.cfg.JWT.RefreshExpiry = d
		}
	}
	if req.JWT.RequireEmailVerification != nil {
		h.cfg.JWT.RequireEmailVerification = *req.JWT.RequireEmailVerification
	}

	// Persist to YAML file
	yamlBytes, err := yaml.Marshal(h.cfg)
	if err == nil {
		if writeErr := os.WriteFile(h.configPath, yamlBytes, 0644); writeErr != nil {
			log.Printf("[AUTHKIT] Warning: could not write %s: %v", h.configPath, writeErr)
		}
	}

	// Hot-reload OAuth providers
	h.oauthManager.Clear()
	if h.cfg.OAuth.Google.Enabled && h.cfg.OAuth.Google.ClientID != "" {
		h.oauthManager.Register(oauth.NewGoogleProvider(h.cfg.OAuth.Google))
	}
	if h.cfg.OAuth.GitHub.Enabled && h.cfg.OAuth.GitHub.ClientID != "" {
		h.oauthManager.Register(oauth.NewGitHubProvider(h.cfg.OAuth.GitHub))
	}
	if h.cfg.OAuth.Firebase.Enabled && h.cfg.OAuth.Firebase.ProjectID != "" {
		h.oauthManager.Register(oauth.NewFirebaseProvider(h.cfg.OAuth.Firebase))
	}

	// Hot-reload Email service
	newEmailSvc, err := email.NewEmailService(h.cfg.Email, "AuthKit")
	if err == nil {
		h.emailService.SetService(newEmailSvc)
	}

	// Hot-reload Schema service
	h.schemaService.UpdateSchema(h.cfg.Schema)

	log.Printf("[AUTHKIT] Configuration updated and hot-reloaded successfully by admin.")
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"status":  "success",
		"message": "Configuration updated and hot-reloaded successfully",
	})
}

type TestEmailRequest struct {
	ToEmail  string             `json:"to_email"`
	Provider string             `json:"provider,omitempty"`
	SMTP     *config.SMTPConfig `json:"smtp,omitempty"`
	Resend   *config.ResendConfig `json:"resend,omitempty"`
	FromEmail string            `json:"from_email,omitempty"`
	FromName  string            `json:"from_name,omitempty"`
}

// TestEmail sends a real test email to verify remote SMTP or email delivery
func (h *ConfigHandler) TestEmail(w http.ResponseWriter, r *http.Request) {
	var req TestEmailRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid request body: "+err.Error())
		return
	}

	if req.ToEmail == "" {
		writeJSONError(w, http.StatusBadRequest, "Recipient 'to_email' is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()

	// If draft SMTP credentials were provided in the request, test with those draft settings
	if req.SMTP != nil && req.SMTP.Host != "" {
		draftCfg := config.EmailConfig{
			Provider:  "smtp",
			FromEmail: req.FromEmail,
			FromName:  req.FromName,
			SMTP:      *req.SMTP,
		}
		if draftCfg.FromEmail == "" {
			draftCfg.FromEmail = h.cfg.Email.FromEmail
		}
		if draftCfg.FromName == "" {
			draftCfg.FromName = h.cfg.Email.FromName
		}
		// If password is blank or masked, fallback to saved password
		if draftCfg.SMTP.Password == "" || draftCfg.SMTP.Password == "••••••••" {
			draftCfg.SMTP.Password = h.cfg.Email.SMTP.Password
		}

		tester := email.NewSMTPService(draftCfg, "AuthKit")
		if err := tester.SendTestEmail(ctx, req.ToEmail); err != nil {
			writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("Remote SMTP test failed: %v", err))
			return
		}

		writeJSONResponse(w, http.StatusOK, map[string]interface{}{
			"success": true,
			"message": fmt.Sprintf("Test email sent successfully to %s via remote SMTP (%s:%d)", req.ToEmail, draftCfg.SMTP.Host, draftCfg.SMTP.Port),
		})
		return
	}

	// Otherwise, test using the active configured email service
	if err := h.emailService.SendTestEmail(ctx, req.ToEmail); err != nil {
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("Email delivery test failed: %v", err))
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": fmt.Sprintf("Test email sent successfully to %s via provider '%s'", req.ToEmail, h.cfg.Email.Provider),
	})
}
