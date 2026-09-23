package db

import (
	"context"
	"errors"

	"authkit/internal/domain"
)

var (
	ErrNotFound       = errors.New("record not found")
	ErrDuplicateEmail = errors.New("user with this email already exists")
	ErrTokenExpired   = errors.New("token has expired")
	ErrTokenInvalid   = errors.New("invalid or used token")
)

// UserFilter defines search and pagination parameters
type UserFilter struct {
	Query     string
	Role      *domain.Role
	Status    *domain.UserStatus
	Page      int
	PageSize  int
	SortBy    string
	SortOrder string // "ASC" or "DESC"
}

// Database is the unified repository interface for all supported storage engines
type Database interface {
	// Lifecycle
	Connect(ctx context.Context) error
	Migrate(ctx context.Context) error
	Close() error
	Type() string
	Ping(ctx context.Context) error

	// User operations
	CreateUser(ctx context.Context, user *domain.User) error
	GetUserByID(ctx context.Context, id string) (*domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	UpdateUser(ctx context.Context, user *domain.User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, filter UserFilter) ([]domain.User, int64, error)
	CountUsers(ctx context.Context) (int64, error)

	// Session operations
	CreateSession(ctx context.Context, session *domain.Session) error
	GetSessionByID(ctx context.Context, id string) (*domain.Session, error)
	GetSessionByTokenHash(ctx context.Context, tokenHash string) (*domain.Session, error)
	RevokeSession(ctx context.Context, id string) error
	RevokeAllUserSessions(ctx context.Context, userID string) error
	DeleteExpiredSessions(ctx context.Context) error

	// Verification and OTP tokens
	CreateVerificationToken(ctx context.Context, token *domain.VerificationToken) error
	GetVerificationToken(ctx context.Context, tokenHash string, tokenType domain.TokenType) (*domain.VerificationToken, error)
	GetVerificationCode(ctx context.Context, email string, code string, tokenType domain.TokenType) (*domain.VerificationToken, error)
	MarkTokenUsed(ctx context.Context, id string) error
	DeleteExpiredTokens(ctx context.Context) error

	// OAuth accounts
	CreateOAuthAccount(ctx context.Context, account *domain.OAuthAccount) error
	GetOAuthAccount(ctx context.Context, provider domain.OAuthProvider, providerUserID string) (*domain.OAuthAccount, error)
	GetOAuthAccountsByUserID(ctx context.Context, userID string) ([]domain.OAuthAccount, error)
	DeleteOAuthAccount(ctx context.Context, id string) error

	// Audit logs
	CreateAuditLog(ctx context.Context, log *domain.AuditLog) error
	ListAuditLogs(ctx context.Context, userID string, limit, offset int) ([]domain.AuditLog, error)
}
