package domain

import (
	"time"
)

// Session represents an active user session or refresh token record
type Session struct {
	ID           string    `json:"id" bson:"_id"`
	UserID       string    `json:"user_id" bson:"user_id"`
	RefreshToken string    `json:"-" bson:"refresh_token_hash"` // Hashed token
	UserAgent    string    `json:"user_agent" bson:"user_agent"`
	ClientIP     string    `json:"client_ip" bson:"client_ip"`
	IsRevoked    bool      `json:"is_revoked" bson:"is_revoked"`
	ExpiresAt    time.Time `json:"expires_at" bson:"expires_at"`
	CreatedAt    time.Time `json:"created_at" bson:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" bson:"updated_at"`
}

// IsExpired checks if session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}
