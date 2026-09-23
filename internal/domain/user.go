package domain

import (
	"encoding/json"
	"time"
)

// Role defines user access level
type Role string

const (
	RoleUser      Role = "user"
	RoleAdmin     Role = "admin"
	RoleSuperAdmin Role = "superadmin"
)

// UserStatus represents user account status
type UserStatus string

const (
	StatusActive    UserStatus = "active"
	StatusPending   UserStatus = "pending"
	StatusSuspended UserStatus = "suspended"
)

// User is the core user entity in AuthKit.
// Custom schema attributes are dynamically stored in Metadata (JSON / BSON).
type User struct {
	ID            string                 `json:"id" bson:"_id"`
	Email         string                 `json:"email" bson:"email"`
	PasswordHash  string                 `json:"-" bson:"password_hash,omitempty"`
	Role          Role                   `json:"role" bson:"role"`
	Status        UserStatus             `json:"status" bson:"status"`
	EmailVerified bool                   `json:"email_verified" bson:"email_verified"`
	Metadata      map[string]interface{} `json:"metadata" bson:"metadata"`
	CreatedAt     time.Time              `json:"created_at" bson:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at" bson:"updated_at"`
	LastLoginAt   *time.Time             `json:"last_login_at,omitempty" bson:"last_login_at,omitempty"`
}

// UserPublic is the sanitized user representation returned by public APIs
type UserPublic struct {
	ID            string                 `json:"id"`
	Email         string                 `json:"email"`
	Role          Role                   `json:"role"`
	Status        UserStatus             `json:"status"`
	EmailVerified bool                   `json:"email_verified"`
	Metadata      map[string]interface{} `json:"metadata"`
	CreatedAt     time.Time              `json:"created_at"`
	UpdatedAt     time.Time              `json:"updated_at"`
	LastLoginAt   *time.Time             `json:"last_login_at,omitempty"`
}

// ToPublic converts User to UserPublic omitting sensitive data
func (u *User) ToPublic() UserPublic {
	meta := u.Metadata
	if meta == nil {
		meta = make(map[string]interface{})
	}
	return UserPublic{
		ID:            u.ID,
		Email:         u.Email,
		Role:          u.Role,
		Status:        u.Status,
		EmailVerified: u.EmailVerified,
		Metadata:      meta,
		CreatedAt:     u.CreatedAt,
		UpdatedAt:     u.UpdatedAt,
		LastLoginAt:   u.LastLoginAt,
	}
}

// MetadataJSON returns JSON bytes for relational database storage
func (u *User) MetadataJSON() ([]byte, error) {
	if u.Metadata == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(u.Metadata)
}

// SetMetadataFromJSON sets metadata from JSON bytes
func (u *User) SetMetadataFromJSON(data []byte) error {
	if len(data) == 0 {
		u.Metadata = make(map[string]interface{})
		return nil
	}
	return json.Unmarshal(data, &u.Metadata)
}
