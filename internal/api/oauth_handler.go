package api

import (
	"encoding/json"
	"fmt"
	"net/http"

	"authkit/internal/config"
	"authkit/internal/domain"
	"authkit/internal/oauth"
	"authkit/internal/service"
	"github.com/go-chi/chi/v5"
)

type OAuthHandler struct {
	cfg          *config.Config
	oauthService *service.OAuthService
	oauthManager *oauth.Manager
}

func NewOAuthHandler(cfg *config.Config, oauthService *service.OAuthService, om *oauth.Manager) *OAuthHandler {
	return &OAuthHandler{
		cfg:          cfg,
		oauthService: oauthService,
		oauthManager: om,
	}
}

// ListProviders returns configured OAuth providers
func (h *OAuthHandler) ListProviders(w http.ResponseWriter, r *http.Request) {
	providers := h.oauthManager.EnabledProviders()
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"providers": providers,
	})
}

// Authorize redirects user to third-party OAuth provider
func (h *OAuthHandler) Authorize(w http.ResponseWriter, r *http.Request) {
	providerName := domain.OAuthProvider(chi.URLParam(r, "provider"))
	redirectURI := r.URL.Query().Get("redirect_uri")

	url, state, err := h.oauthService.GetAuthURL(providerName, redirectURI)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	// Store state in temporary cookie for CSRF verification
	http.SetCookie(w, &http.Cookie{
		Name:     "oauth_state",
		Value:    state,
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// Callback processes OAuth code exchange
func (h *OAuthHandler) Callback(w http.ResponseWriter, r *http.Request) {
	providerName := domain.OAuthProvider(chi.URLParam(r, "provider"))
	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")
	redirectURI := r.URL.Query().Get("redirect_uri")

	if code == "" {
		errParam := r.URL.Query().Get("error")
		errDesc := r.URL.Query().Get("error_description")
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("OAuth error: %s (%s)", errParam, errDesc))
		return
	}

	// Verify state if state cookie was present
	cookie, _ := r.Cookie("oauth_state")
	if cookie != nil && cookie.Value != "" && state != "" && cookie.Value != state {
		writeJSONError(w, http.StatusForbidden, "Invalid OAuth state parameter (possible CSRF)")
		return
	}

	resp, err := h.oauthService.HandleCallback(r.Context(), providerName, code, redirectURI, r.UserAgent(), getClientIP(r))
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	setAuthCookies(w, resp.AccessToken, resp.RefreshToken, resp.ExpiresIn)

	// If app redirect is requested, redirect with token fragment or cookie
	appRedirect := r.URL.Query().Get("app_redirect")
	if appRedirect != "" {
		targetURL := fmt.Sprintf("%s#access_token=%s&refresh_token=%s", appRedirect, resp.AccessToken, resp.RefreshToken)
		http.Redirect(w, r, targetURL, http.StatusTemporaryRedirect)
		return
	}

	writeJSONResponse(w, http.StatusOK, resp)
}

// VerifyFirebaseToken accepts a client-provided Firebase ID token and authenticates the user
func (h *OAuthHandler) VerifyFirebaseToken(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	if body.IDToken == "" {
		writeJSONError(w, http.StatusBadRequest, "id_token is required")
		return
	}

	resp, err := h.oauthService.HandleFirebaseToken(r.Context(), body.IDToken, r.UserAgent(), getClientIP(r))
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, err.Error())
		return
	}

	setAuthCookies(w, resp.AccessToken, resp.RefreshToken, resp.ExpiresIn)
	writeJSONResponse(w, http.StatusOK, resp)
}
