package crypto

import (
	"testing"
)

func TestHashAndCheckPassword(t *testing.T) {
	password := "SecretP@ssword123!"
	hash, err := HashPassword(password)
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}

	if hash == password {
		t.Fatalf("Password was not hashed")
	}

	if !CheckPassword(password, hash) {
		t.Fatalf("CheckPassword returned false for correct password")
	}

	if CheckPassword("WrongPassword", hash) {
		t.Fatalf("CheckPassword returned true for wrong password")
	}
}

func TestGenerateOTP(t *testing.T) {
	otp, err := GenerateOTP(6)
	if err != nil {
		t.Fatalf("GenerateOTP failed: %v", err)
	}

	if len(otp) != 6 {
		t.Fatalf("Expected OTP length 6, got %d", len(otp))
	}

	for _, ch := range otp {
		if ch < '0' || ch > '9' {
			t.Fatalf("Expected numeric character, got %c", ch)
		}
	}
}

func TestHashToken(t *testing.T) {
	tok := "random_token_12345"
	h1 := HashToken(tok)
	h2 := HashToken(tok)
	if h1 != h2 {
		t.Fatalf("HashToken must be deterministic")
	}
	if len(h1) != 64 { // SHA-256 hex
		t.Fatalf("Expected 64 hex characters, got %d", len(h1))
	}
}
