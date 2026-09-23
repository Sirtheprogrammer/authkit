package sqlite

import (
	"context"
	"os"
	"testing"
	"time"

	"authkit/internal/db"
	"authkit/internal/domain"
)

func TestSQLiteRepository(t *testing.T) {
	tmpFile := "./test_authkit.db"
	defer os.Remove(tmpFile)

	d := New(tmpFile)
	ctx := context.Background()

	if err := d.Connect(ctx); err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	defer d.Close()

	if err := d.Migrate(ctx); err != nil {
		t.Fatalf("Failed to migrate: %v", err)
	}

	// 1. Create User
	now := time.Now().UTC().Truncate(time.Second)
	u := &domain.User{
		ID:            "u-1",
		Email:         "sqlite_test@example.com",
		PasswordHash:  "hash123",
		Role:          domain.RoleUser,
		Status:        domain.StatusActive,
		EmailVerified: false,
		Metadata: map[string]interface{}{
			"tier": "pro",
			"score": 42.0,
		},
		CreatedAt: now,
		UpdatedAt: now,
	}

	if err := d.CreateUser(ctx, u); err != nil {
		t.Fatalf("CreateUser failed: %v", err)
	}

	// Duplicate email should fail
	if err := d.CreateUser(ctx, u); err != db.ErrDuplicateEmail {
		t.Fatalf("Expected ErrDuplicateEmail, got %v", err)
	}

	// 2. Get User
	fetched, err := d.GetUserByEmail(ctx, "sqlite_test@example.com")
	if err != nil {
		t.Fatalf("GetUserByEmail failed: %v", err)
	}
	if fetched.ID != "u-1" {
		t.Fatalf("Expected ID u-1, got %s", fetched.ID)
	}
	if fetched.Metadata["tier"] != "pro" {
		t.Fatalf("Expected metadata tier pro, got %v", fetched.Metadata["tier"])
	}

	// 3. Update User
	fetched.Role = domain.RoleAdmin
	fetched.EmailVerified = true
	if err := d.UpdateUser(ctx, fetched); err != nil {
		t.Fatalf("UpdateUser failed: %v", err)
	}

	updated, _ := d.GetUserByID(ctx, "u-1")
	if updated.Role != domain.RoleAdmin || !updated.EmailVerified {
		t.Fatalf("Update not reflected: role=%s, verified=%v", updated.Role, updated.EmailVerified)
	}

	// 4. Session Operations
	sess := &domain.Session{
		ID:           "s-1",
		UserID:       "u-1",
		RefreshToken: "hashed_refresh_123",
		UserAgent:    "TestAgent",
		ClientIP:     "127.0.0.1",
		IsRevoked:    false,
		ExpiresAt:    now.Add(24 * time.Hour),
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := d.CreateSession(ctx, sess); err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}

	foundSess, err := d.GetSessionByTokenHash(ctx, "hashed_refresh_123")
	if err != nil {
		t.Fatalf("GetSessionByTokenHash failed: %v", err)
	}
	if foundSess.ID != "s-1" {
		t.Fatalf("Expected session s-1, got %s", foundSess.ID)
	}

	// Revoke Session
	if err := d.RevokeSession(ctx, "s-1"); err != nil {
		t.Fatalf("RevokeSession failed: %v", err)
	}
	revokedSess, _ := d.GetSessionByID(ctx, "s-1")
	if !revokedSess.IsRevoked {
		t.Fatalf("Expected session to be revoked")
	}

	// 5. Verification Token
	vt := &domain.VerificationToken{
		ID:        "vt-1",
		UserID:    "u-1",
		Email:     "sqlite_test@example.com",
		TokenHash: "vt_hash_123",
		Code:      "123456",
		Type:      domain.TokenTypeEmailVerification,
		Used:      false,
		ExpiresAt: now.Add(1 * time.Hour),
		CreatedAt: now,
	}

	if err := d.CreateVerificationToken(ctx, vt); err != nil {
		t.Fatalf("CreateVerificationToken failed: %v", err)
	}

	foundVT, err := d.GetVerificationCode(ctx, "sqlite_test@example.com", "123456", domain.TokenTypeEmailVerification)
	if err != nil {
		t.Fatalf("GetVerificationCode failed: %v", err)
	}
	if foundVT.ID != "vt-1" {
		t.Fatalf("Expected vt-1, got %s", foundVT.ID)
	}

	// 6. List Users
	users, total, err := d.ListUsers(ctx, db.UserFilter{Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("ListUsers failed: %v", err)
	}
	if total != 1 || len(users) != 1 {
		t.Fatalf("Expected 1 user, got total=%d, len=%d", total, len(users))
	}
}
