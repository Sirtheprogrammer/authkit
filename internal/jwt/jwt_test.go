package jwt

import (
	"testing"
	"time"

	"authkit/internal/domain"
)

func TestTokenManagerRS256(t *testing.T) {
	tm, err := NewTokenManager(Config{
		Issuer:           "authkit-test",
		AccessExpiry:     10 * time.Minute,
		SigningAlgorithm: "RS256",
		KeyID:            "test-key-1",
	})
	if err != nil {
		t.Fatalf("Failed to create token manager: %v", err)
	}

	user := &domain.User{
		ID:            "user-100",
		Email:         "test@example.com",
		Role:          domain.RoleUser,
		Status:        domain.StatusActive,
		EmailVerified: true,
		Metadata: map[string]interface{}{
			"department": "Engineering",
		},
	}

	token, expiresAt, err := tm.GenerateAccessToken(user, "sess-1")
	if err != nil {
		t.Fatalf("Failed to generate access token: %v", err)
	}

	if time.Now().After(expiresAt) {
		t.Fatalf("ExpiresAt must be in the future")
	}

	claims, err := tm.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("Failed to verify access token: %v", err)
	}

	if claims.UserID != user.ID {
		t.Fatalf("Expected UserID %s, got %s", user.ID, claims.UserID)
	}
	if claims.Email != user.Email {
		t.Fatalf("Expected Email %s, got %s", user.Email, claims.Email)
	}
	if claims.Role != user.Role {
		t.Fatalf("Expected Role %s, got %s", user.Role, claims.Role)
	}
	if claims.Metadata["department"] != "Engineering" {
		t.Fatalf("Expected department Engineering, got %v", claims.Metadata["department"])
	}

	// Verify JWKS
	jwks := tm.GetJWKS()
	if len(jwks.Keys) != 1 {
		t.Fatalf("Expected 1 key in JWKS, got %d", len(jwks.Keys))
	}
	if jwks.Keys[0].Kid != "test-key-1" {
		t.Fatalf("Expected Kid test-key-1, got %s", jwks.Keys[0].Kid)
	}
	if jwks.Keys[0].Alg != "RS256" {
		t.Fatalf("Expected Alg RS256, got %s", jwks.Keys[0].Alg)
	}
}

func TestTokenManagerHS256(t *testing.T) {
	tm, err := NewTokenManager(Config{
		Issuer:           "authkit-test",
		SigningAlgorithm: "HS256",
		HMACSecret:       "a_very_secret_key_1234567890",
	})
	if err != nil {
		t.Fatalf("Failed to create token manager: %v", err)
	}

	user := &domain.User{
		ID:    "user-200",
		Email: "hs256@example.com",
		Role:  domain.RoleAdmin,
	}

	token, _, err := tm.GenerateAccessToken(user, "sess-2")
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}

	claims, err := tm.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("Failed to verify token: %v", err)
	}
	if claims.UserID != "user-200" {
		t.Fatalf("Expected user-200, got %s", claims.UserID)
	}
}
