package domain

import (
	"time"
)

// TokenType classifies one-time security tokens
type TokenType string

const (
	TokenTypeEmailVerification TokenType = "email_verification"
	TokenTypePasswordReset     TokenType = "password_reset"
)

// VerificationToken represents an OTP code or cryptographic link token
type VerificationToken struct {
	ID        string    `json:"id" bson:"_id"`
	UserID    string    `json:"user_id" bson:"user_id"`
	Email     string    `json:"email" bson:"email"`
	TokenHash string    `json:"-" bson:"token_hash"`
	Code      string    `json:"-" bson:"code"` // 6-digit OTP code (hashed or stored for fast match)
	Type      TokenType `json:"type" bson:"type"`
	Used      bool      `json:"used" bson:"used"`
	ExpiresAt time.Time `json:"expires_at" bson:"expires_at"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
}

// IsValid checks if token is not expired and not used
func (vt *VerificationToken) IsValid() bool {
	return !vt.Used && time.Now().Before(vt.ExpiresAt)
}

// AuditLog tracks authentication and administrative events
type AuditLog struct {
	ID        string    `json:"id" bson:"_id"`
	UserID    string    `json:"user_id,omitempty" bson:"user_id,omitempty"`
	Action    string    `json:"action" bson:"action"`
	IPAddress string    `json:"ip_address" bson:"ip_address"`
	UserAgent string    `json:"user_agent" bson:"user_agent"`
	Metadata  string    `json:"metadata,omitempty" bson:"metadata,omitempty"`
	CreatedAt time.Time `json:"created_at" bson:"created_at"`
}
