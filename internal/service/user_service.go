package service

import (
	"context"
	"fmt"
	"strings"
	"time"

	"authkit/internal/crypto"
	"authkit/internal/db"
	"authkit/internal/domain"
	"github.com/google/uuid"
)

// UserService provides administrative operations for managing users
type UserService struct {
	database      db.Database
	schemaService *SchemaService
}

func NewUserService(database db.Database, ss *SchemaService) *UserService {
	return &UserService{
		database:      database,
		schemaService: ss,
	}
}

// ListUsers retrieves paginated user list
func (u *UserService) ListUsers(ctx context.Context, filter db.UserFilter) ([]domain.UserPublic, int64, error) {
	users, total, err := u.database.ListUsers(ctx, filter)
	if err != nil {
		return nil, 0, err
	}

	result := make([]domain.UserPublic, len(users))
	for i := range users {
		result[i] = users[i].ToPublic()
	}
	return result, total, nil
}

// GetUser retrieves user by ID
func (u *UserService) GetUser(ctx context.Context, id string) (*domain.UserPublic, error) {
	user, err := u.database.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}
	pub := user.ToPublic()
	return &pub, nil
}

// CreateUserRequest defines payload for admin to provision a user
type CreateUserRequest struct {
	Email         string                 `json:"email"`
	Password      string                 `json:"password"`
	Role          domain.Role            `json:"role"`
	Status        domain.UserStatus      `json:"status"`
	EmailVerified bool                   `json:"email_verified"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// CreateUser allows an administrator or MCP tool to create a user
func (u *UserService) CreateUser(ctx context.Context, req CreateUserRequest) (*domain.UserPublic, error) {
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if req.Email == "" {
		return nil, fmt.Errorf("email is required")
	}

	validatedMeta, err := u.schemaService.ValidateUserData(req.Metadata, false)
	if err != nil {
		return nil, err
	}

	var pwdHash string
	if req.Password != "" {
		pwdHash, err = crypto.HashPassword(req.Password)
		if err != nil {
			return nil, err
		}
	}

	role := req.Role
	if role == "" {
		role = domain.RoleUser
	}
	status := req.Status
	if status == "" {
		status = domain.StatusActive
	}

	now := time.Now().UTC()
	user := &domain.User{
		ID:            uuid.New().String(),
		Email:         req.Email,
		PasswordHash:  pwdHash,
		Role:          role,
		Status:        status,
		EmailVerified: req.EmailVerified,
		Metadata:      validatedMeta,
		CreatedAt:     now,
		UpdatedAt:     now,
	}

	if err := u.database.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	pub := user.ToPublic()
	return &pub, nil
}

// UpdateUserRequest allows updating role, status, or custom metadata
type UpdateUserRequest struct {
	Role          *domain.Role           `json:"role,omitempty"`
	Status        *domain.UserStatus     `json:"status,omitempty"`
	EmailVerified *bool                  `json:"email_verified,omitempty"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
}

// UpdateUser updates user properties
func (u *UserService) UpdateUser(ctx context.Context, id string, req UpdateUserRequest) (*domain.UserPublic, error) {
	user, err := u.database.GetUserByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if req.Role != nil {
		user.Role = *req.Role
	}
	if req.Status != nil {
		user.Status = *req.Status
	}
	if req.EmailVerified != nil {
		user.EmailVerified = *req.EmailVerified
	}
	if req.Metadata != nil {
		validatedMeta, err := u.schemaService.ValidateUserData(req.Metadata, false)
		if err != nil {
			return nil, err
		}
		if user.Metadata == nil {
			user.Metadata = make(map[string]interface{})
		}
		for k, v := range validatedMeta {
			user.Metadata[k] = v
		}
	}

	user.UpdatedAt = time.Now().UTC()
	if err := u.database.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	// If suspended, revoke sessions
	if user.Status == domain.StatusSuspended {
		_ = u.database.RevokeAllUserSessions(ctx, user.ID)
	}

	pub := user.ToPublic()
	return &pub, nil
}

// DeleteUser removes a user and their sessions
func (u *UserService) DeleteUser(ctx context.Context, id string) error {
	return u.database.DeleteUser(ctx, id)
}

// CountUsers returns total user count
func (u *UserService) CountUsers(ctx context.Context) (int64, error) {
	return u.database.CountUsers(ctx)
}
