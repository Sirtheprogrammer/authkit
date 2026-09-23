package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"authkit/internal/config"
	"authkit/internal/domain"
)

// GitHubProvider handles GitHub OAuth authentication
type GitHubProvider struct {
	cfg        config.OAuthProviderConfig
	httpClient *http.Client
}

// NewGitHubProvider creates a GitHub OAuth provider
func NewGitHubProvider(cfg config.OAuthProviderConfig) *GitHubProvider {
	return &GitHubProvider{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
}

func (gh *GitHubProvider) Name() domain.OAuthProvider {
	return domain.ProviderGitHub
}

func (gh *GitHubProvider) GetAuthURL(state, redirectURI string) string {
	if redirectURI == "" {
		redirectURI = gh.cfg.RedirectURL
	}
	params := url.Values{}
	params.Set("client_id", gh.cfg.ClientID)
	params.Set("redirect_uri", redirectURI)
	params.Set("scope", "read:user user:email")
	params.Set("state", state)

	return "https://github.com/login/oauth/authorize?" + params.Encode()
}

type githubTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	Scope       string `json:"scope"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

type githubUserResponse struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
}

type githubEmailItem struct {
	Email      string `json:"email"`
	Primary    bool   `json:"primary"`
	Verified   bool   `json:"verified"`
	Visibility string `json:"visibility"`
}

func (gh *GitHubProvider) Exchange(ctx context.Context, code, redirectURI string) (*domain.OAuthUserInfo, error) {
	if redirectURI == "" {
		redirectURI = gh.cfg.RedirectURL
	}

	data := url.Values{}
	data.Set("code", code)
	data.Set("client_id", gh.cfg.ClientID)
	data.Set("client_secret", gh.cfg.ClientSecret)
	data.Set("redirect_uri", redirectURI)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://github.com/login/oauth/access_token", strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := gh.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token body: %w", err)
	}

	var tokenResp githubTokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	if tokenResp.Error != "" {
		return nil, fmt.Errorf("github oauth error: %s (%s)", tokenResp.Error, tokenResp.ErrorDesc)
	}

	// Fetch user profile
	userReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create user request: %w", err)
	}
	userReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
	userReq.Header.Set("Accept", "application/vnd.github.v3+json")

	userResp, err := gh.httpClient.Do(userReq)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch user: %w", err)
	}
	defer userResp.Body.Close()

	userBody, err := io.ReadAll(userResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read github user: %w", err)
	}

	var ghUser githubUserResponse
	if err := json.Unmarshal(userBody, &ghUser); err != nil {
		return nil, fmt.Errorf("failed to parse github user: %w", err)
	}

	primaryEmail := ghUser.Email
	emailVerified := false

	// If email is not public or not present, fetch from /user/emails
	if primaryEmail == "" {
		emailReq, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.github.com/user/emails", nil)
		if err == nil {
			emailReq.Header.Set("Authorization", "Bearer "+tokenResp.AccessToken)
			emailReq.Header.Set("Accept", "application/vnd.github.v3+json")
			emailResp, err := gh.httpClient.Do(emailReq)
			if err == nil {
				defer emailResp.Body.Close()
				var emails []githubEmailItem
				if err := json.NewDecoder(emailResp.Body).Decode(&emails); err == nil {
					for _, em := range emails {
						if em.Primary {
							primaryEmail = em.Email
							emailVerified = em.Verified
							break
						}
					}
					if primaryEmail == "" && len(emails) > 0 {
						primaryEmail = emails[0].Email
						emailVerified = emails[0].Verified
					}
				}
			}
		}
	} else {
		emailVerified = true
	}

	displayName := ghUser.Name
	if displayName == "" {
		displayName = ghUser.Login
	}

	var raw map[string]interface{}
	_ = json.Unmarshal(userBody, &raw)

	return &domain.OAuthUserInfo{
		Provider:       domain.ProviderGitHub,
		ProviderUserID: strconv.FormatInt(ghUser.ID, 10),
		Email:          primaryEmail,
		EmailVerified:  emailVerified,
		Name:           displayName,
		AvatarURL:      ghUser.AvatarURL,
		RawData:        raw,
	}, nil
}
