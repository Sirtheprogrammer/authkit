package config

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"authkit/internal/domain"
	"gopkg.in/yaml.v3"
)

// Config represents complete AuthKit configuration
type Config struct {
	Server   ServerConfig   `json:"server" yaml:"server"`
	Database DatabaseConfig `json:"database" yaml:"database"`
	JWT      JWTConfig      `json:"jwt" yaml:"jwt"`
	Schema   SchemaConfig   `json:"schema" yaml:"schema"`
	OAuth    OAuthConfig    `json:"oauth" yaml:"oauth"`
	Email    EmailConfig    `json:"email" yaml:"email"`
	MCP      MCPConfig      `json:"mcp" yaml:"mcp"`
}

type ServerConfig struct {
	Port           int      `json:"port" yaml:"port"`
	Host           string   `json:"host" yaml:"host"`
	BaseURL        string   `json:"base_url" yaml:"base_url"`
	Environment    string   `json:"environment" yaml:"environment"` // "development", "production"
	AllowedOrigins []string `json:"allowed_origins" yaml:"allowed_origins"`
}

type DatabaseConfig struct {
	Type     string `json:"type" yaml:"type"` // "sqlite", "postgres", "mysql", "mongodb"
	URL      string `json:"url" yaml:"url"`
	Filepath string `json:"filepath" yaml:"filepath"` // for SQLite
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	User     string `json:"user" yaml:"user"`
	Password string `json:"password" yaml:"password"`
	Database string `json:"database" yaml:"database"`
	SSLMode  string `json:"sslmode" yaml:"sslmode"`
}

type JWTConfig struct {
	Algorithm                string        `json:"algorithm" yaml:"algorithm"` // "RS256" or "HS256"
	Issuer                   string        `json:"issuer" yaml:"issuer"`
	KeyID                    string        `json:"key_id" yaml:"key_id"`
	PrivateKeyPEM            string        `json:"private_key_pem" yaml:"private_key_pem"`
	PublicKeyPEM             string        `json:"public_key_pem" yaml:"public_key_pem"`
	HMACSecret               string        `json:"hmac_secret" yaml:"hmac_secret"`
	AccessExpiry             time.Duration `json:"access_expiry" yaml:"access_expiry"`
	RefreshExpiry            time.Duration `json:"refresh_expiry" yaml:"refresh_expiry"`
	RequireEmailVerification bool          `json:"require_email_verification" yaml:"require_email_verification"`
}

type SchemaConfig struct {
	Strict bool                     `json:"strict" yaml:"strict"`
	Fields []domain.FieldDefinition `json:"fields" yaml:"fields"`
}

type OAuthConfig struct {
	Google   OAuthProviderConfig `json:"google" yaml:"google"`
	Firebase FirebaseConfig      `json:"firebase" yaml:"firebase"`
	GitHub   OAuthProviderConfig `json:"github" yaml:"github"`
}

type OAuthProviderConfig struct {
	Enabled      bool   `json:"enabled" yaml:"enabled"`
	ClientID     string `json:"client_id" yaml:"client_id"`
	ClientSecret string `json:"client_secret" yaml:"client_secret"`
	RedirectURL  string `json:"redirect_url" yaml:"redirect_url"`
}

type FirebaseConfig struct {
	Enabled            bool   `json:"enabled" yaml:"enabled"`
	ProjectID          string `json:"project_id" yaml:"project_id"`
	ServiceAccountJSON string `json:"service_account_json" yaml:"service_account_json"`
}

type EmailConfig struct {
	Provider string       `json:"provider" yaml:"provider"` // "mock", "smtp", "resend"
	FromEmail string      `json:"from_email" yaml:"from_email"`
	FromName  string      `json:"from_name" yaml:"from_name"`
	SMTP      SMTPConfig  `json:"smtp" yaml:"smtp"`
	Resend    ResendConfig `json:"resend" yaml:"resend"`
}

type SMTPConfig struct {
	Host     string `json:"host" yaml:"host"`
	Port     int    `json:"port" yaml:"port"`
	Username string `json:"username" yaml:"username"`
	Password string `json:"password" yaml:"password"`
	Secure   bool   `json:"secure" yaml:"secure"` // true for SSL (465), false for STARTTLS (587)
}

type ResendConfig struct {
	APIKey string `json:"api_key" yaml:"api_key"`
}

type MCPConfig struct {
	Enabled   bool   `json:"enabled" yaml:"enabled"`
	AuthToken string `json:"auth_token" yaml:"auth_token"`
}

// DefaultConfig returns ready-to-run defaults (SQLite, mock emails, port 8080)
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:           8080,
			Host:           "0.0.0.0",
			BaseURL:        "http://localhost:8080",
			Environment:    "development",
			AllowedOrigins: []string{"*"},
		},
		Database: DatabaseConfig{
			Type:     "sqlite",
			Filepath: "./authkit.db",
		},
		JWT: JWTConfig{
			Algorithm:     "RS256",
			Issuer:        "authkit",
			KeyID:         "authkit-key-1",
			AccessExpiry:  15 * time.Minute,
			RefreshExpiry: 7 * 24 * time.Hour,
		},
		Schema: SchemaConfig{
			Strict: false,
			Fields: []domain.FieldDefinition{},
		},
		OAuth: OAuthConfig{
			Google:   OAuthProviderConfig{Enabled: false},
			Firebase: FirebaseConfig{Enabled: false},
			GitHub:   OAuthProviderConfig{Enabled: false},
		},
		Email: EmailConfig{
			Provider:  "mock",
			FromEmail: "auth@authkit.local",
			FromName:  "AuthKit",
			SMTP: SMTPConfig{
				Port: 587,
			},
		},
		MCP: MCPConfig{
			Enabled: true,
		},
	}
}

// LoadConfig loads configuration from optional file path and applies environment variables
func LoadConfig(filepath string) (*Config, error) {
	cfg := DefaultConfig()

	if filepath != "" {
		if _, err := os.Stat(filepath); err == nil {
			data, err := os.ReadFile(filepath)
			if err != nil {
				return nil, fmt.Errorf("failed to read config file %s: %w", filepath, err)
			}
			if err := yaml.Unmarshal(data, cfg); err != nil {
				return nil, fmt.Errorf("failed to parse yaml config: %w", err)
			}
		}
	}

	// Environment variable overrides
	applyEnvOverrides(cfg)

	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if val := os.Getenv("PORT"); val != "" {
		if p, err := strconv.Atoi(val); err == nil {
			cfg.Server.Port = p
		}
	}
	if val := os.Getenv("HOST"); val != "" {
		cfg.Server.Host = val
	}
	if val := os.Getenv("BASE_URL"); val != "" {
		cfg.Server.BaseURL = strings.TrimSuffix(val, "/")
	}
	if val := os.Getenv("ENV"); val != "" {
		cfg.Server.Environment = val
	}

	// Database overrides
	if val := os.Getenv("DB_TYPE"); val != "" {
		cfg.Database.Type = val
	}
	if val := os.Getenv("DATABASE_URL"); val != "" {
		cfg.Database.URL = val
	}
	if val := os.Getenv("DB_FILE"); val != "" {
		cfg.Database.Filepath = val
	}
	if val := os.Getenv("DB_HOST"); val != "" {
		cfg.Database.Host = val
	}
	if val := os.Getenv("DB_PORT"); val != "" {
		if p, err := strconv.Atoi(val); err == nil {
			cfg.Database.Port = p
		}
	}
	if val := os.Getenv("DB_USER"); val != "" {
		cfg.Database.User = val
	}
	if val := os.Getenv("DB_PASSWORD"); val != "" {
		cfg.Database.Password = val
	}
	if val := os.Getenv("DB_NAME"); val != "" {
		cfg.Database.Database = val
	}

	// JWT overrides
	if val := os.Getenv("JWT_ALGORITHM"); val != "" {
		cfg.JWT.Algorithm = val
	}
	if val := os.Getenv("JWT_SECRET"); val != "" {
		cfg.JWT.HMACSecret = val
	}
	if val := os.Getenv("JWT_PRIVATE_KEY"); val != "" {
		cfg.JWT.PrivateKeyPEM = val
	}
	if val := os.Getenv("JWT_PUBLIC_KEY"); val != "" {
		cfg.JWT.PublicKeyPEM = val
	}
	if val := os.Getenv("JWT_ISSUER"); val != "" {
		cfg.JWT.Issuer = val
	}
	if val := os.Getenv("REQUIRE_EMAIL_VERIFICATION"); val != "" {
		cfg.JWT.RequireEmailVerification = strings.ToLower(val) == "true" || val == "1"
	}

	// Google OAuth overrides
	if val := os.Getenv("GOOGLE_CLIENT_ID"); val != "" {
		cfg.OAuth.Google.ClientID = val
		cfg.OAuth.Google.Enabled = true
	}
	if val := os.Getenv("GOOGLE_CLIENT_SECRET"); val != "" {
		cfg.OAuth.Google.ClientSecret = val
	}
	if val := os.Getenv("GOOGLE_REDIRECT_URL"); val != "" {
		cfg.OAuth.Google.RedirectURL = val
	}

	// Firebase Auth overrides
	if val := os.Getenv("FIREBASE_PROJECT_ID"); val != "" {
		cfg.OAuth.Firebase.ProjectID = val
		cfg.OAuth.Firebase.Enabled = true
	}
	if val := os.Getenv("FIREBASE_SERVICE_ACCOUNT_JSON"); val != "" {
		cfg.OAuth.Firebase.ServiceAccountJSON = val
	}

	// GitHub OAuth overrides
	if val := os.Getenv("GITHUB_CLIENT_ID"); val != "" {
		cfg.OAuth.GitHub.ClientID = val
		cfg.OAuth.GitHub.Enabled = true
	}
	if val := os.Getenv("GITHUB_CLIENT_SECRET"); val != "" {
		cfg.OAuth.GitHub.ClientSecret = val
	}
	if val := os.Getenv("GITHUB_REDIRECT_URL"); val != "" {
		cfg.OAuth.GitHub.RedirectURL = val
	}

	// Email overrides
	if val := os.Getenv("EMAIL_PROVIDER"); val != "" {
		cfg.Email.Provider = val
	}
	if val := os.Getenv("EMAIL_FROM"); val != "" {
		cfg.Email.FromEmail = val
	}
	if val := os.Getenv("EMAIL_FROM_NAME"); val != "" {
		cfg.Email.FromName = val
	}
	if val := os.Getenv("SMTP_HOST"); val != "" {
		cfg.Email.SMTP.Host = val
		if cfg.Email.Provider == "mock" {
			cfg.Email.Provider = "smtp"
		}
	}
	if val := os.Getenv("SMTP_PORT"); val != "" {
		if p, err := strconv.Atoi(val); err == nil {
			cfg.Email.SMTP.Port = p
		}
	}
	if val := os.Getenv("SMTP_USERNAME"); val != "" {
		cfg.Email.SMTP.Username = val
	}
	if val := os.Getenv("SMTP_PASSWORD"); val != "" {
		cfg.Email.SMTP.Password = val
	}
	if val := os.Getenv("SMTP_SECURE"); val != "" {
		cfg.Email.SMTP.Secure = strings.ToLower(val) == "true" || val == "1"
	}
	if val := os.Getenv("RESEND_API_KEY"); val != "" {
		cfg.Email.Resend.APIKey = val
		if cfg.Email.Provider == "mock" {
			cfg.Email.Provider = "resend"
		}
	}

	// MCP overrides
	if val := os.Getenv("MCP_ENABLED"); val != "" {
		cfg.MCP.Enabled = strings.ToLower(val) == "true" || val == "1"
	}
	if val := os.Getenv("MCP_AUTH_TOKEN"); val != "" {
		cfg.MCP.AuthToken = val
	}
}
