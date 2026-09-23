package cli

import (
	"context"
	"fmt"
	"strings"
	"time"

	"authkit/internal/config"
	"authkit/internal/crypto"
	"authkit/internal/db/factory"
	"authkit/internal/domain"
	"authkit/internal/jwt"
	"github.com/google/uuid"
)

// CreateSuperAdmin provisions an initial superadmin account
func CreateSuperAdmin(cfg *config.Config, emailStr, password string) error {
	ctx := context.Background()
	database, err := factory.NewDatabase(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("failed to connect to database: %w", err)
	}
	defer database.Close()

	emailStr = strings.TrimSpace(strings.ToLower(emailStr))
	if emailStr == "" || password == "" {
		return fmt.Errorf("both email and password are required")
	}

	existing, _ := database.GetUserByEmail(ctx, emailStr)
	if existing != nil {
		existing.Role = domain.RoleSuperAdmin
		existing.Status = domain.StatusActive
		existing.EmailVerified = true
		pwdHash, _ := crypto.HashPassword(password)
		existing.PasswordHash = pwdHash
		existing.UpdatedAt = time.Now().UTC()
		if err := database.UpdateUser(ctx, existing); err != nil {
			return err
		}
		fmt.Printf("[OK] Existing user %s elevated to superadmin successfully.\n", emailStr)
		return nil
	}

	pwdHash, err := crypto.HashPassword(password)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	user := &domain.User{
		ID:            uuid.New().String(),
		Email:         emailStr,
		PasswordHash:  pwdHash,
		Role:          domain.RoleSuperAdmin,
		Status:        domain.StatusActive,
		EmailVerified: true,
		Metadata: map[string]interface{}{
			"name": "Super Admin",
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := database.CreateUser(ctx, user); err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	fmt.Printf("[OK] Superadmin account created: %s (ID: %s)\n", emailStr, user.ID)
	return nil
}

// GenerateTestToken generates and prints a valid stateless JWT token
func GenerateTestToken(cfg *config.Config, userID, emailStr, roleStr string) error {
	tm, err := jwt.NewTokenManager(jwt.Config{
		Issuer:           cfg.JWT.Issuer,
		AccessExpiry:     cfg.JWT.AccessExpiry,
		RefreshExpiry:    cfg.JWT.RefreshExpiry,
		SigningAlgorithm: cfg.JWT.Algorithm,
		RSAPrivateKeyPEM: cfg.JWT.PrivateKeyPEM,
		HMACSecret:       cfg.JWT.HMACSecret,
		KeyID:            cfg.JWT.KeyID,
	})
	if err != nil {
		return fmt.Errorf("failed to initialize token manager: %w", err)
	}

	if userID == "" {
		userID = uuid.New().String()
	}
	if emailStr == "" {
		emailStr = "admin@authkit.local"
	}
	role := domain.Role(roleStr)
	if role == "" {
		role = domain.RoleSuperAdmin
	}

	user := &domain.User{
		ID:            userID,
		Email:         emailStr,
		Role:          role,
		Status:        domain.StatusActive,
		EmailVerified: true,
		Metadata: map[string]interface{}{
			"generated_by": "authkit-cli",
		},
	}

	token, expiresAt, err := tm.GenerateAccessToken(user, uuid.New().String())
	if err != nil {
		return err
	}

	fmt.Println("Stateless JWT Access Token:")
	fmt.Println(token)
	fmt.Printf("\nClaims: sub=%s, email=%s, role=%s, expires_at=%s\n",
		user.ID, user.Email, user.Role, expiresAt.Format(time.RFC3339))
	return nil
}
