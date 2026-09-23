package domain

import (
	"time"
)

// OAuthProvider represents supported external identity providers
type OAuthProvider string

const (
	ProviderGoogle   OAuthProvider = "google"
	ProviderFirebase OAuthProvider = "firebase"
	ProviderGitHub   OAuthProvider = "github"
)

// OAuthAccount connects an AuthKit User with an external OAuth/OIDC identity
type OAuthAccount struct {
	ID             string        `json:"id" bson:"_id"`
	UserID         string        `json:"user_id" bson:"user_id"`
	Provider       OAuthProvider `json:"provider" bson:"provider"`
	ProviderUserID string        `json:"provider_user_id" bson:"provider_user_id"`
	Email          string        `json:"email" bson:"email"`
	AvatarURL      string        `json:"avatar_url,omitempty" bson:"avatar_url,omitempty"`
	CreatedAt      time.Time     `json:"created_at" bson:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at" bson:"updated_at"`
}

// OAuthUserInfo represents standardized user profile from any OAuth provider
type OAuthUserInfo struct {
	Provider       OAuthProvider
	ProviderUserID string
	Email          string
	EmailVerified  bool
	Name           string
	AvatarURL      string
	RawData        map[string]interface{}
}
