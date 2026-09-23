package service

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"authkit/internal/config"
	"authkit/internal/crypto"
	"authkit/internal/db"
	"authkit/internal/domain"
	"authkit/internal/email"
	"authkit/internal/jwt"
	"github.com/google/uuid"
)

var (
	ErrInvalidCredentials     = errors.New("invalid email or password")
	ErrAccountSuspended       = errors.New("account has been suspended")
	ErrEmailNotVerified       = errors.New("email address has not been verified")
	ErrWeakPassword           = errors.New("password must be at least 8 characters long")
	ErrInvalidEmail           = errors.New("invalid email address format")
	ErrInvalidRefreshToken    = errors.New("invalid or expired refresh token")
	ErrInvalidResetToken      = errors.New("invalid or expired reset token or code")
	ErrInvalidVerifyToken     = errors.New("invalid or expired verification token or code")
)

type SignupRequest struct {
	Email     string                 `json:"email"`
	Password  string                 `json:"password"`
	Metadata  map[string]interface{} `json:"metadata,omitempty"`
	UserAgent string                 `json:"-"`
	ClientIP  string                 `json:"-"`
}

type LoginRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	UserAgent string `json:"-"`
	ClientIP  string `json:"-"`
}

type AuthResponse struct {
	User         domain.UserPublic `json:"user"`
	AccessToken  string            `json:"access_token"`
	RefreshToken string            `json:"refresh_token"`
	TokenType    string            `json:"token_type"`
	ExpiresIn    int64             `json:"expires_in"`
}

type AuthService struct {
	cfg           *config.Config
	database      db.Database
	tokenManager  *jwt.TokenManager
	schemaService *SchemaService
	emailService  email.Service
}

func NewAuthService(
	cfg *config.Config,
	database db.Database,
	tm *jwt.TokenManager,
	ss *SchemaService,
	es email.Service,
) *AuthService {
	return &AuthService{
		cfg:           cfg,
		database:      database,
		tokenManager:  tm,
		schemaService: ss,
		emailService:  es,
	}
}

// Signup registers a new user, validates dynamic schema attributes, and issues credentials
func (s *AuthService) Signup(ctx context.Context, req SignupRequest) (*AuthResponse, error) {
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	if _, err := mail.ParseAddress(req.Email); err != nil {
		return nil, ErrInvalidEmail
	}

	if len(req.Password) < 8 {
		return nil, ErrWeakPassword
	}

	// Validate custom fields
	validatedMeta, err := s.schemaService.ValidateUserData(req.Metadata, true)
	if err != nil {
		return nil, err
	}

	// Hash password
	pwdHash, err := crypto.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	now := time.Now().UTC()
	userID := uuid.New().String()

	status := domain.StatusActive
	emailVerified := false
	if s.cfg.JWT.RequireEmailVerification {
		status = domain.StatusPending
	}

	user := &domain.User{
		ID:            userID,
		Email:         req.Email,
		PasswordHash:  pwdHash,
		Role:          domain.RoleUser,
		Status:        status,
		EmailVerified: emailVerified,
		Metadata:      validatedMeta,
		CreatedAt:     now,
		UpdatedAt:     now,
		LastLoginAt:   &now,
	}

	if err := s.database.CreateUser(ctx, user); err != nil {
		return nil, err
	}

	// Log audit event
	_ = s.database.CreateAuditLog(ctx, &domain.AuditLog{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Action:    "user.signup",
		IPAddress: req.ClientIP,
		UserAgent: req.UserAgent,
		CreatedAt: now,
	})

	// Dispatch email verification or welcome email
	if s.cfg.JWT.RequireEmailVerification {
		go s.dispatchVerification(user)
	} else {
		userName, _ := user.Metadata["name"].(string)
		go s.emailService.SendWelcomeEmail(context.Background(), user.Email, userName)
	}

	// Create session and return tokens
	return s.createSessionAndResponse(ctx, user, req.UserAgent, req.ClientIP)
}

// Login authenticates a user by email and password
func (s *AuthService) Login(ctx context.Context, req LoginRequest) (*AuthResponse, error) {
	req.Email = strings.TrimSpace(strings.ToLower(req.Email))
	user, err := s.database.GetUserByEmail(ctx, req.Email)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return nil, ErrInvalidCredentials
		}
		return nil, err
	}

	if user.PasswordHash == "" || !crypto.CheckPassword(req.Password, user.PasswordHash) {
		return nil, ErrInvalidCredentials
	}

	if user.Status == domain.StatusSuspended {
		return nil, ErrAccountSuspended
	}

	if s.cfg.JWT.RequireEmailVerification && !user.EmailVerified {
		return nil, ErrEmailNotVerified
	}

	now := time.Now().UTC()
	user.LastLoginAt = &now
	_ = s.database.UpdateUser(ctx, user)

	_ = s.database.CreateAuditLog(ctx, &domain.AuditLog{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Action:    "user.login",
		IPAddress: req.ClientIP,
		UserAgent: req.UserAgent,
		CreatedAt: now,
	})

	return s.createSessionAndResponse(ctx, user, req.UserAgent, req.ClientIP)
}

// RefreshToken rotates refresh token and generates new stateless access token
func (s *AuthService) RefreshToken(ctx context.Context, rawRefreshToken, userAgent, clientIP string) (*AuthResponse, error) {
	tokenHash := crypto.HashToken(rawRefreshToken)

	session, err := s.database.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}

	if session.IsRevoked || session.IsExpired() {
		return nil, ErrInvalidRefreshToken
	}

	// Revoke old session (Rotation)
	_ = s.database.RevokeSession(ctx, session.ID)

	user, err := s.database.GetUserByID(ctx, session.UserID)
	if err != nil {
		return nil, ErrInvalidRefreshToken
	}

	if user.Status == domain.StatusSuspended {
		return nil, ErrAccountSuspended
	}

	return s.createSessionAndResponse(ctx, user, userAgent, clientIP)
}

// Logout invalidates a session
func (s *AuthService) Logout(ctx context.Context, rawRefreshToken string) error {
	tokenHash := crypto.HashToken(rawRefreshToken)
	session, err := s.database.GetSessionByTokenHash(ctx, tokenHash)
	if err != nil {
		return nil // idempotent logout
	}
	return s.database.RevokeSession(ctx, session.ID)
}

// ForgotPassword triggers password reset email with secure token and OTP code
func (s *AuthService) ForgotPassword(ctx context.Context, emailStr string) error {
	emailStr = strings.TrimSpace(strings.ToLower(emailStr))
	user, err := s.database.GetUserByEmail(ctx, emailStr)
	if err != nil {
		// Return success to avoid email enumeration
		return nil
	}

	rawToken, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return err
	}
	otpCode, err := crypto.GenerateOTP(6)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	vt := &domain.VerificationToken{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Email:     user.Email,
		TokenHash: crypto.HashToken(rawToken),
		Code:      otpCode,
		Type:      domain.TokenTypePasswordReset,
		Used:      false,
		ExpiresAt: now.Add(30 * time.Minute),
		CreatedAt: now,
	}

	if err := s.database.CreateVerificationToken(ctx, vt); err != nil {
		return err
	}

	resetURL := fmt.Sprintf("%s/reset-password?token=%s", s.cfg.Server.BaseURL, rawToken)
	userName, _ := user.Metadata["name"].(string)

	go func() {
		_ = s.emailService.SendPasswordResetEmail(context.Background(), user.Email, userName, otpCode, resetURL)
	}()

	return nil
}

// ResetPassword resets password via token or 6-digit OTP code
func (s *AuthService) ResetPassword(ctx context.Context, tokenOrCode, emailStr, newPassword string) error {
	if len(newPassword) < 8 {
		return ErrWeakPassword
	}

	var vt *domain.VerificationToken
	var err error

	// Try matching by token hash first
	vt, err = s.database.GetVerificationToken(ctx, crypto.HashToken(tokenOrCode), domain.TokenTypePasswordReset)
	if err != nil && emailStr != "" {
		// Try matching by 6-digit OTP code
		vt, err = s.database.GetVerificationCode(ctx, emailStr, tokenOrCode, domain.TokenTypePasswordReset)
	}

	if err != nil || vt == nil || !vt.IsValid() {
		return ErrInvalidResetToken
	}

	// Hash new password
	newHash, err := crypto.HashPassword(newPassword)
	if err != nil {
		return err
	}

	user, err := s.database.GetUserByID(ctx, vt.UserID)
	if err != nil {
		return err
	}

	user.PasswordHash = newHash
	user.UpdatedAt = time.Now().UTC()
	if err := s.database.UpdateUser(ctx, user); err != nil {
		return err
	}

	// Mark token used
	_ = s.database.MarkTokenUsed(ctx, vt.ID)

	// Invalidate all existing sessions for security
	_ = s.database.RevokeAllUserSessions(ctx, user.ID)

	return nil
}

// VerifyEmail verifies user email with token or OTP code
func (s *AuthService) VerifyEmail(ctx context.Context, tokenOrCode, emailStr string) error {
	var vt *domain.VerificationToken
	var err error

	vt, err = s.database.GetVerificationToken(ctx, crypto.HashToken(tokenOrCode), domain.TokenTypeEmailVerification)
	if err != nil && emailStr != "" {
		vt, err = s.database.GetVerificationCode(ctx, emailStr, tokenOrCode, domain.TokenTypeEmailVerification)
	}

	if err != nil || vt == nil || !vt.IsValid() {
		return ErrInvalidVerifyToken
	}

	user, err := s.database.GetUserByID(ctx, vt.UserID)
	if err != nil {
		return err
	}

	user.EmailVerified = true
	if user.Status == domain.StatusPending {
		user.Status = domain.StatusActive
	}
	user.UpdatedAt = time.Now().UTC()

	if err := s.database.UpdateUser(ctx, user); err != nil {
		return err
	}

	_ = s.database.MarkTokenUsed(ctx, vt.ID)
	return nil
}

// ResendVerification triggers a new verification email
func (s *AuthService) ResendVerification(ctx context.Context, emailStr string) error {
	emailStr = strings.TrimSpace(strings.ToLower(emailStr))
	user, err := s.database.GetUserByEmail(ctx, emailStr)
	if err != nil {
		return nil
	}
	if user.EmailVerified {
		return nil
	}
	go s.dispatchVerification(user)
	return nil
}

// GetMe returns current authenticated user profile
func (s *AuthService) GetMe(ctx context.Context, userID string) (*domain.UserPublic, error) {
	user, err := s.database.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	pub := user.ToPublic()
	return &pub, nil
}

// UpdateMe updates current user's dynamic custom fields
func (s *AuthService) UpdateMe(ctx context.Context, userID string, metadata map[string]interface{}) (*domain.UserPublic, error) {
	user, err := s.database.GetUserByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	// Validate metadata (not signup, so optional fields can be left out)
	validatedMeta, err := s.schemaService.ValidateUserData(metadata, false)
	if err != nil {
		return nil, err
	}

	if user.Metadata == nil {
		user.Metadata = make(map[string]interface{})
	}
	for k, v := range validatedMeta {
		user.Metadata[k] = v
	}
	user.UpdatedAt = time.Now().UTC()

	if err := s.database.UpdateUser(ctx, user); err != nil {
		return nil, err
	}

	pub := user.ToPublic()
	return &pub, nil
}

func (s *AuthService) createSessionAndResponse(ctx context.Context, user *domain.User, userAgent, clientIP string) (*AuthResponse, error) {
	sessionID := uuid.New().String()
	rawRefreshToken, err := crypto.GenerateRandomHex(40)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	sess := &domain.Session{
		ID:           sessionID,
		UserID:       user.ID,
		RefreshToken: crypto.HashToken(rawRefreshToken),
		UserAgent:    userAgent,
		ClientIP:     clientIP,
		IsRevoked:    false,
		ExpiresAt:    now.Add(s.tokenManager.RefreshTTL()),
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.database.CreateSession(ctx, sess); err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	accessToken, _, err := s.tokenManager.GenerateAccessToken(user, sessionID)
	if err != nil {
		return nil, fmt.Errorf("failed to generate access token: %w", err)
	}

	return &AuthResponse{
		User:         user.ToPublic(),
		AccessToken:  accessToken,
		RefreshToken: rawRefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int64(s.tokenManager.AccessTTL().Seconds()),
	}, nil
}

func (s *AuthService) dispatchVerification(user *domain.User) {
	rawToken, err := crypto.GenerateRandomHex(32)
	if err != nil {
		return
	}
	otpCode, err := crypto.GenerateOTP(6)
	if err != nil {
		return
	}

	now := time.Now().UTC()
	vt := &domain.VerificationToken{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Email:     user.Email,
		TokenHash: crypto.HashToken(rawToken),
		Code:      otpCode,
		Type:      domain.TokenTypeEmailVerification,
		Used:      false,
		ExpiresAt: now.Add(24 * time.Hour),
		CreatedAt: now,
	}

	if err := s.database.CreateVerificationToken(context.Background(), vt); err != nil {
		return
	}

	verifyURL := fmt.Sprintf("%s/verify-email?token=%s", s.cfg.Server.BaseURL, rawToken)
	userName, _ := user.Metadata["name"].(string)

	_ = s.emailService.SendVerificationEmail(context.Background(), user.Email, userName, otpCode, verifyURL)
}
