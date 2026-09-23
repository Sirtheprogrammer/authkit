package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"authkit/internal/db"
	"authkit/internal/service"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

// Signup handles user registration
func (h *AuthHandler) Signup(w http.ResponseWriter, r *http.Request) {
	var req service.SignupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	req.UserAgent = r.UserAgent()
	req.ClientIP = getClientIP(r)

	resp, err := h.authService.Signup(r.Context(), req)
	if err != nil {
		if errors.Is(err, db.ErrDuplicateEmail) {
			writeJSONError(w, http.StatusConflict, "User with this email already exists")
			return
		}
		if errors.Is(err, service.ErrInvalidEmail) || errors.Is(err, service.ErrWeakPassword) {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if strings.Contains(err.Error(), "schema validation error") || strings.Contains(err.Error(), "required") {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "Failed to register user: "+err.Error())
		return
	}

	setAuthCookies(w, resp.AccessToken, resp.RefreshToken, resp.ExpiresIn)
	writeJSONResponse(w, http.StatusCreated, resp)
}

// Login handles user login
func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req service.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	req.UserAgent = r.UserAgent()
	req.ClientIP = getClientIP(r)

	resp, err := h.authService.Login(r.Context(), req)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			writeJSONError(w, http.StatusUnauthorized, "Invalid email or password")
			return
		}
		if errors.Is(err, service.ErrAccountSuspended) {
			writeJSONError(w, http.StatusForbidden, "Account is suspended")
			return
		}
		if errors.Is(err, service.ErrEmailNotVerified) {
			writeJSONError(w, http.StatusForbidden, "Email address has not been verified")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, "Login failed: "+err.Error())
		return
	}

	setAuthCookies(w, resp.AccessToken, resp.RefreshToken, resp.ExpiresIn)
	writeJSONResponse(w, http.StatusOK, resp)
}

// Refresh handles token rotation
func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	rawToken := body.RefreshToken
	if rawToken == "" {
		cookie, err := r.Cookie("authkit_refresh_token")
		if err == nil && cookie != nil {
			rawToken = cookie.Value
		}
	}

	if rawToken == "" {
		writeJSONError(w, http.StatusBadRequest, "Refresh token is required")
		return
	}

	resp, err := h.authService.RefreshToken(r.Context(), rawToken, r.UserAgent(), getClientIP(r))
	if err != nil {
		clearAuthCookies(w)
		writeJSONError(w, http.StatusUnauthorized, "Invalid or expired refresh token")
		return
	}

	setAuthCookies(w, resp.AccessToken, resp.RefreshToken, resp.ExpiresIn)
	writeJSONResponse(w, http.StatusOK, resp)
}

// Logout invalidates session and clears cookies
func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	rawToken := body.RefreshToken
	if rawToken == "" {
		cookie, err := r.Cookie("authkit_refresh_token")
		if err == nil && cookie != nil {
			rawToken = cookie.Value
		}
	}

	if rawToken != "" {
		_ = h.authService.Logout(r.Context(), rawToken)
	}

	clearAuthCookies(w)
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Logged out successfully",
	})
}

// GetMe returns current user
func (h *AuthHandler) GetMe(w http.ResponseWriter, r *http.Request) {
	claims := GetUserClaims(r.Context())
	if claims == nil {
		writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	user, err := h.authService.GetMe(r.Context(), claims.UserID)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "User not found")
		return
	}

	writeJSONResponse(w, http.StatusOK, user)
}

// UpdateMe updates current user's custom schema attributes
func (h *AuthHandler) UpdateMe(w http.ResponseWriter, r *http.Request) {
	claims := GetUserClaims(r.Context())
	if claims == nil {
		writeJSONError(w, http.StatusUnauthorized, "Unauthorized")
		return
	}

	var body struct {
		Metadata map[string]interface{} `json:"metadata"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	user, err := h.authService.UpdateMe(r.Context(), claims.UserID, body.Metadata)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSONResponse(w, http.StatusOK, user)
}

// ForgotPassword requests reset link/code
func (h *AuthHandler) ForgotPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	_ = h.authService.ForgotPassword(r.Context(), body.Email)
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "If the email is registered, password reset instructions have been sent.",
	})
}

// ResetPassword resets password
func (h *AuthHandler) ResetPassword(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token       string `json:"token"`
		Code        string `json:"code"`
		Email       string `json:"email"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	tokenOrCode := body.Token
	if tokenOrCode == "" {
		tokenOrCode = body.Code
	}

	if tokenOrCode == "" || body.NewPassword == "" {
		writeJSONError(w, http.StatusBadRequest, "Token/code and new_password are required")
		return
	}

	err := h.authService.ResetPassword(r.Context(), tokenOrCode, body.Email, body.NewPassword)
	if err != nil {
		if errors.Is(err, service.ErrInvalidResetToken) {
			writeJSONError(w, http.StatusBadRequest, "Invalid or expired reset token or code")
			return
		}
		if errors.Is(err, service.ErrWeakPassword) {
			writeJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	clearAuthCookies(w)
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Password has been successfully reset. Please log in with your new password.",
	})
}

// ConfirmEmail verifies email address
func (h *AuthHandler) ConfirmEmail(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Token string `json:"token"`
		Code  string `json:"code"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	tokenOrCode := body.Token
	if tokenOrCode == "" {
		tokenOrCode = body.Code
	}

	if tokenOrCode == "" {
		writeJSONError(w, http.StatusBadRequest, "Token or code is required")
		return
	}

	err := h.authService.VerifyEmail(r.Context(), tokenOrCode, body.Email)
	if err != nil {
		if errors.Is(err, service.ErrInvalidVerifyToken) {
			writeJSONError(w, http.StatusBadRequest, "Invalid or expired verification token or code")
			return
		}
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "Email address successfully verified.",
	})
}

// ResendVerification re-dispatches verification email
func (h *AuthHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	_ = h.authService.ResendVerification(r.Context(), body.Email)
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "If the account exists and is not verified, a new verification email has been sent.",
	})
}

func getClientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" {
		parts := strings.Split(fwd, ",")
		return strings.TrimSpace(parts[0])
	}
	if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
		return realIP
	}
	return r.RemoteAddr
}

func setAuthCookies(w http.ResponseWriter, accessToken, refreshToken string, accessMaxAge int64) {
	http.SetCookie(w, &http.Cookie{
		Name:     "authkit_access_token",
		Value:    accessToken,
		Path:     "/",
		MaxAge:   int(accessMaxAge),
		HttpOnly: true,
		Secure:   false, // Can be true in TLS
		SameSite: http.SameSiteLaxMode,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "authkit_refresh_token",
		Value:    refreshToken,
		Path:     "/",
		MaxAge:   7 * 24 * 3600,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
}

func clearAuthCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     "authkit_access_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})
	http.SetCookie(w, &http.Cookie{
		Name:     "authkit_refresh_token",
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		Expires:  time.Unix(0, 0),
		HttpOnly: true,
	})
}

func writeJSONResponse(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}
