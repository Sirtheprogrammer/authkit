package jwt

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	"authkit/internal/domain"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// UserClaims defines JWT payload containing stateless user identity
type UserClaims struct {
	UserID        string                 `json:"sub"`
	Email         string                 `json:"email"`
	Role          domain.Role            `json:"role"`
	Status        domain.UserStatus      `json:"status"`
	EmailVerified bool                   `json:"email_verified"`
	Metadata      map[string]interface{} `json:"metadata,omitempty"`
	SessionID     string                 `json:"sid,omitempty"`
	jwt.RegisteredClaims
}

// TokenPair represents both short-lived access token and long-lived refresh token
type TokenPair struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int64     `json:"expires_in"` // seconds
	ExpiresAt    time.Time `json:"expires_at"`
}

// TokenManager handles generation, signing, and verification of stateless JWTs
type TokenManager struct {
	issuer            string
	accessTTL         time.Duration
	refreshTTL        time.Duration
	signingMethod     jwt.SigningMethod
	rsaPrivateKey     *rsa.PrivateKey
	rsaPublicKey      *rsa.PublicKey
	hmacSecret        []byte
	keyID             string
}

// Config defines JWT manager options
type Config struct {
	Issuer            string
	AccessExpiry      time.Duration
	RefreshExpiry     time.Duration
	SigningAlgorithm  string // "RS256" or "HS256"
	RSAPrivateKeyPEM  string
	RSAPublicKeyPEM   string
	HMACSecret        string
	KeyID             string
}

// NewTokenManager creates and initializes a JWT TokenManager
func NewTokenManager(cfg Config) (*TokenManager, error) {
	if cfg.AccessExpiry <= 0 {
		cfg.AccessExpiry = 15 * time.Minute
	}
	if cfg.RefreshExpiry <= 0 {
		cfg.RefreshExpiry = 7 * 24 * time.Hour
	}
	if cfg.Issuer == "" {
		cfg.Issuer = "authkit"
	}
	if cfg.KeyID == "" {
		cfg.KeyID = "authkit-key-1"
	}

	tm := &TokenManager{
		issuer:     cfg.Issuer,
		accessTTL:  cfg.AccessExpiry,
		refreshTTL: cfg.RefreshExpiry,
		keyID:      cfg.KeyID,
	}

	if cfg.SigningAlgorithm == "HS256" {
		if len(cfg.HMACSecret) < 16 {
			return nil, errors.New("HMAC secret must be at least 16 characters long")
		}
		tm.signingMethod = jwt.SigningMethodHS256
		tm.hmacSecret = []byte(cfg.HMACSecret)
		return tm, nil
	}

	// Default to RS256
	tm.signingMethod = jwt.SigningMethodRS256

	if cfg.RSAPrivateKeyPEM != "" {
		block, _ := pem.Decode([]byte(cfg.RSAPrivateKeyPEM))
		if block == nil {
			return nil, errors.New("failed to parse RSA private key PEM")
		}
		privKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			pkcs8Key, err2 := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err2 != nil {
				return nil, fmt.Errorf("failed to parse private key: %w (pkcs8: %v)", err, err2)
			}
			var ok bool
			privKey, ok = pkcs8Key.(*rsa.PrivateKey)
			if !ok {
				return nil, errors.New("not an RSA private key")
			}
		}
		tm.rsaPrivateKey = privKey
		tm.rsaPublicKey = &privKey.PublicKey
	} else {
		// Generate an ephemeral RSA 2048 key pair
		privKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to auto-generate RSA key: %w", err)
		}
		tm.rsaPrivateKey = privKey
		tm.rsaPublicKey = &privKey.PublicKey
	}

	return tm, nil
}

// GenerateAccessToken signs a stateless JWT containing the user claims
func (tm *TokenManager) GenerateAccessToken(user *domain.User, sessionID string) (string, time.Time, error) {
	now := time.Now().UTC()
	expiresAt := now.Add(tm.accessTTL)

	meta := user.Metadata
	if meta == nil {
		meta = make(map[string]interface{})
	}

	claims := UserClaims{
		UserID:        user.ID,
		Email:         user.Email,
		Role:          user.Role,
		Status:        user.Status,
		EmailVerified: user.EmailVerified,
		Metadata:      meta,
		SessionID:     sessionID,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    tm.issuer,
			Subject:   user.ID,
			Audience:  jwt.ClaimStrings{tm.issuer + "-api"},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
			ID:        uuid.New().String(),
		},
	}

	token := jwt.NewWithClaims(tm.signingMethod, claims)
	token.Header["kid"] = tm.keyID

	var signed string
	var err error

	if tm.signingMethod == jwt.SigningMethodHS256 {
		signed, err = token.SignedString(tm.hmacSecret)
	} else {
		signed, err = token.SignedString(tm.rsaPrivateKey)
	}

	if err != nil {
		return "", time.Time{}, fmt.Errorf("failed to sign access token: %w", err)
	}

	return signed, expiresAt, nil
}

// VerifyAccessToken decodes and validates a stateless JWT
func (tm *TokenManager) VerifyAccessToken(tokenString string) (*UserClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
		if tm.signingMethod == jwt.SigningMethodHS256 {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
			}
			return tm.hmacSecret, nil
		}

		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return tm.rsaPublicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	claims, ok := token.Claims.(*UserClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

// GetPublicKey returns the RSA public key if in RS256 mode
func (tm *TokenManager) GetPublicKey() *rsa.PublicKey {
	return tm.rsaPublicKey
}

// KeyID returns the key ID used in JWT header
func (tm *TokenManager) KeyID() string {
	return tm.keyID
}

// AccessTTL returns access token duration
func (tm *TokenManager) AccessTTL() time.Duration {
	return tm.accessTTL
}

// RefreshTTL returns refresh token duration
func (tm *TokenManager) RefreshTTL() time.Duration {
	return tm.refreshTTL
}
