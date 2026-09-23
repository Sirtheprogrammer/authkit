package service

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"authkit/internal/config"
	"authkit/internal/crypto"
	"authkit/internal/db"
	"authkit/internal/domain"
	"authkit/internal/jwt"
	"authkit/internal/oauth"
	"github.com/google/uuid"
)

// OAuthService handles third-party OAuth flows and account linking
type OAuthService struct {
	cfg          *config.Config
	database     db.Database
	tokenManager *jwt.TokenManager
	oauthManager *oauth.Manager
}

func NewOAuthService(
	cfg *config.Config,
	database db.Database,
	tm *jwt.TokenManager,
	om *oauth.Manager,
) *OAuthService {
	return &OAuthService{
		cfg:          cfg,
		database:     database,
		tokenManager: tm,
		oauthManager: om,
	}
}

// GetAuthURL generates authorization redirect URL for an OAuth provider
func (s *OAuthService) GetAuthURL(providerName domain.OAuthProvider, redirectURI string) (string, string, error) {
	provider, err := s.oauthManager.Get(providerName)
	if err != nil {
		return "", "", err
	}

	state, err := crypto.GenerateRandomHex(16)
	if err != nil {
		return "", "", err
	}

	url := provider.GetAuthURL(state, redirectURI)
	return url, state, nil
}

// HandleCallback exchanges authorization code for user profile, links accounts, and issues session
func (s *OAuthService) HandleCallback(ctx context.Context, providerName domain.OAuthProvider, code, redirectURI, userAgent, clientIP string) (*AuthResponse, error) {
	provider, err := s.oauthManager.Get(providerName)
	if err != nil {
		return nil, err
	}

	userInfo, err := provider.Exchange(ctx, code, redirectURI)
	if err != nil {
		return nil, fmt.Errorf("oauth exchange failed: %w", err)
	}

	return s.processOAuthUser(ctx, userInfo, userAgent, clientIP)
}

// HandleFirebaseToken verifies a client-provided Firebase ID token and provisions or signs in user
func (s *OAuthService) HandleFirebaseToken(ctx context.Context, idToken, userAgent, clientIP string) (*AuthResponse, error) {
	provider, err := s.oauthManager.Get(domain.ProviderFirebase)
	if err != nil {
		return nil, err
	}

	fbProvider, ok := provider.(*oauth.FirebaseProvider)
	if !ok {
		return nil, errors.New("firebase provider type assertion failed")
	}

	userInfo, err := fbProvider.VerifyIDToken(ctx, idToken)
	if err != nil {
		return nil, fmt.Errorf("firebase verification failed: %w", err)
	}

	return s.processOAuthUser(ctx, userInfo, userAgent, clientIP)
}

func (s *OAuthService) processOAuthUser(ctx context.Context, userInfo *domain.OAuthUserInfo, userAgent, clientIP string) (*AuthResponse, error) {
	now := time.Now().UTC()

	// 1. Check if OAuth account already exists
	oauthAcc, err := s.database.GetOAuthAccount(ctx, userInfo.Provider, userInfo.ProviderUserID)
	if err == nil && oauthAcc != nil {
		// Existing linked account: fetch user
		user, err := s.database.GetUserByID(ctx, oauthAcc.UserID)
		if err != nil {
			return nil, err
		}

		if user.Status == domain.StatusSuspended {
			return nil, ErrAccountSuspended
		}

		user.LastLoginAt = &now
		_ = s.database.UpdateUser(ctx, user)

		return s.createSessionAndResponse(ctx, user, userAgent, clientIP)
	}

	// 2. Check if a user with this email already exists
	emailStr := strings.TrimSpace(strings.ToLower(userInfo.Email))
	if emailStr == "" {
		return nil, fmt.Errorf("no email provided by oauth provider %s", userInfo.Provider)
	}

	user, err := s.database.GetUserByEmail(ctx, emailStr)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			// 3. Create brand new user
			metadata := make(map[string]interface{})
			if userInfo.Name != "" {
				metadata["name"] = userInfo.Name
			}
			if userInfo.AvatarURL != "" {
				metadata["avatar_url"] = userInfo.AvatarURL
			}

			user = &domain.User{
				ID:            uuid.New().String(),
				Email:         emailStr,
				Role:          domain.RoleUser,
				Status:        domain.StatusActive,
				EmailVerified: userInfo.EmailVerified,
				Metadata:      metadata,
				CreatedAt:     now,
				UpdatedAt:     now,
				LastLoginAt:   &now,
			}

			if err := s.database.CreateUser(ctx, user); err != nil {
				return nil, err
			}
		} else {
			return nil, err
		}
	} else {
		// Existing email account: mark email verified if provider verified it
		if userInfo.EmailVerified && !user.EmailVerified {
			user.EmailVerified = true
			user.UpdatedAt = now
			_ = s.database.UpdateUser(ctx, user)
		}
	}

	// 4. Link OAuth account
	newOAuthAcc := &domain.OAuthAccount{
		ID:             uuid.New().String(),
		UserID:         user.ID,
		Provider:       userInfo.Provider,
		ProviderUserID: userInfo.ProviderUserID,
		Email:          emailStr,
		AvatarURL:      userInfo.AvatarURL,
		CreatedAt:      now,
		UpdatedAt:      now,
	}

	_ = s.database.CreateOAuthAccount(ctx, newOAuthAcc)

	_ = s.database.CreateAuditLog(ctx, &domain.AuditLog{
		ID:        uuid.New().String(),
		UserID:    user.ID,
		Action:    fmt.Sprintf("oauth.login.%s", userInfo.Provider),
		IPAddress: clientIP,
		UserAgent: userAgent,
		CreatedAt: now,
	})

	return s.createSessionAndResponse(ctx, user, userAgent, clientIP)
}

func (s *OAuthService) createSessionAndResponse(ctx context.Context, user *domain.User, userAgent, clientIP string) (*AuthResponse, error) {
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
