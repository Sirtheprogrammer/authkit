package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"authkit/internal/config"
	"authkit/internal/domain"
)

// GoogleProvider handles Google Cloud OAuth2 / OIDC authentication
type GoogleProvider struct {
	cfg        config.OAuthProviderConfig
	httpClient *http.Client
}

// NewGoogleProvider creates a Google OAuth provider
func NewGoogleProvider(cfg config.OAuthProviderConfig) *GoogleProvider {
	return &GoogleProvider{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (g *GoogleProvider) Name() domain.OAuthProvider {
	return domain.ProviderGoogle
}

func (g *GoogleProvider) GetAuthURL(state, redirectURI string) string {
	if redirectURI == "" {
		redirectURI = g.cfg.RedirectURL
	}
	params := url.Values{}
	params.Set("client_id", g.cfg.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("response_type", "code")
	params.Set("scope", "openid email profile")
	params.Set("state", state)
	params.Set("access_type", "offline")
	params.Set("prompt", "select_account")

	return "https://accounts.google.com/o/oauth2/v2/auth?" + params.Encode()
}

type googleTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	IDToken     string `json:"id_token"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

type googleUserInfoResponse struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func (g *GoogleProvider) Exchange(ctx context.Context, code, redirectURI string) (*domain.OAuthUserInfo, error) {
	if redirectURI == "" {
		redirectURI = g.cfg.RedirectURL
	}

	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", g.cfg.ClientID)
	data.Set("client_secret", g.cfg.ClientSecret)
	data.Set("redirect_uri", redirectURI)
	data.Set("grant_type", "authorization_code")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://oauth2.googleapis.com/token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := g.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	var tokenResp googleTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("oauth error: %s - %s", tokenResp.Error, tokenResp.ErrorDesc)
	}

	// Fetch user profile
	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://www.googleapis.com/oauth2/v3/userinfo", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create userinfo request: %w", err)
	}
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)

	userResp, err := g.httpClient.Do(userReq)
	if err != nil {
		return nil, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer userResp.Body.Close()

	userBody, err := io.ReadAll(userResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read userinfo: %w", err)
	}

	var userInfo googleUserInfoResponse
	if err := json.Unmarshal(userBody, &userInfo); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo: %w", err)
	}

	if userInfo.Sub == "" {
		return nil, fmt.Errorf("empty google user id")
	}

	var raw map[string]interface{}
	_ = json.Unmarshal(userBody, &raw)

	return &domain.OAuthUserInfo{
		Provider:       domain.ProviderGoogle,
		ProviderUserID: userInfo.Sub,
		Email:          userInfo.Email,
		EmailVerified:  userInfo.EmailVerified,
		Name:           userInfo.Name,
		AvatarURL:      userInfo.Picture,
		RawData:        raw,
	}, nil
}
