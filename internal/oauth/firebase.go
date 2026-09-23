package oauth

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"authkit/internal/config"
	"authkit/internal/domain"
	"github.com/golang-jwt/jwt/v5"
)

// FirebaseProvider handles Firebase Auth token verification and user provisioning
type FirebaseProvider struct {
	cfg        config.FirebaseConfig
	httpClient *http.Client
	mu         sync.RWMutex
	cachedKeys map[string]string
	keysExpire time.Time
}

// NewFirebaseProvider creates a Firebase auth provider
func NewFirebaseProvider(cfg config.FirebaseConfig) *FirebaseProvider {
	return &FirebaseProvider{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
		cachedKeys: make(map[string]string),
	}
}

func (f *FirebaseProvider) Name() domain.OAuthProvider {
	return domain.ProviderFirebase
}

// GetAuthURL is not applicable for Firebase client-token flow, but returns documentation URL
func (f *FirebaseProvider) GetAuthURL(state, redirectURI string) string {
	return ""
}

// Exchange is not directly used for OAuth code flow in Firebase, use VerifyIDToken instead
func (f *FirebaseProvider) Exchange(ctx context.Context, code, redirectURI string) (*domain.OAuthUserInfo, error) {
	return nil, errors.New("firebase uses VerifyIDToken with client-provided ID token")
}

type firebaseClaims struct {
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
	Firebase      struct {
		SignInProvider string `json:"sign_in_provider"`
	} `json:"firebase"`
	jwt.RegisteredClaims
}

// VerifyIDToken validates a Firebase ID token using Google public certificates
func (f *FirebaseProvider) VerifyIDToken(ctx context.Context, idToken string) (*domain.OAuthUserInfo, error) {
	if f.cfg.ProjectID == "" {
		return nil, errors.New("firebase project_id is not configured")
	}

	keys, err := f.getGooglePublicKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch firebase public keys: %w", err)
	}

	token, err := jwt.ParseWithClaims(idToken, &firebaseClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing algorithm: %v", t.Header["alg"])
		}

		kid, ok := t.Header["kid"].(string)
		if !ok || kid == "" {
			return nil, errors.New("firebase token missing kid header")
		}

		certPEM, ok := keys[kid]
		if !ok {
			return nil, fmt.Errorf("public key not found for kid: %s", kid)
		}

		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			return nil, errors.New("failed to parse x509 cert PEM")
		}

		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate: %w", err)
		}

		return cert.PublicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("invalid firebase ID token: %w", err)
	}

	claims, ok := token.Claims.(*firebaseClaims)
	if !ok || !token.Valid {
		return nil, errors.New("invalid firebase token claims")
	}

	// Verify audience matches Project ID
	expectedIssuer := fmt.Sprintf("https://securetoken.google.com/%s", f.cfg.ProjectID)
	if claims.Issuer != expectedIssuer {
		return nil, fmt.Errorf("invalid issuer: expected %s, got %s", expectedIssuer, claims.Issuer)
	}

	matchedAud := false
	for _, aud := range claims.Audience {
		if aud == f.cfg.ProjectID {
			matchedAud = true
			break
		}
	}
	if !matchedAud {
		return nil, fmt.Errorf("invalid audience: expected %s", f.cfg.ProjectID)
	}

	if claims.Subject == "" {
		return nil, errors.New("firebase subject (UID) is empty")
	}

	return &domain.OAuthUserInfo{
		Provider:       domain.ProviderFirebase,
		ProviderUserID: claims.Subject,
		Email:          claims.Email,
		EmailVerified:  claims.EmailVerified,
		Name:           claims.Name,
		AvatarURL:      claims.Picture,
		RawData: map[string]interface{}{
			"firebase_uid": claims.Subject,
			"provider":     claims.Firebase.SignInProvider,
		},
	}, nil
}

func (f *FirebaseProvider) getGooglePublicKeys(ctx context.Context) (map[string]string, error) {
	f.mu.RLock()
	if time.Now().Before(f.keysExpire) && len(f.cachedKeys) > 0 {
		defer f.mu.RUnlock()
		return f.cachedKeys, nil
	}
	f.mu.RUnlock()

	f.mu.Lock()
	defer f.mu.Unlock()

	// Double check after lock
	if time.Now().Before(f.keysExpire) && len(f.cachedKeys) > 0 {
		return f.cachedKeys, nil
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com", nil)
	if err != nil {
		return nil, err
	}

	resp, err := f.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("google cert endpoint returned status %d", resp.StatusCode)
	}

	var keys map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&keys); err != nil {
		return nil, err
	}

	f.cachedKeys = keys
	// Cache for 6 hours
	f.keysExpire = time.Now().Add(6 * time.Hour)

	return keys, nil
}
