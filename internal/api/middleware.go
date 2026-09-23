package api

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"

	"authkit/internal/domain"
	"authkit/internal/jwt"
)

type contextKey string

const (
	UserClaimsContextKey contextKey = "authkit_user_claims"
)

// AuthMiddleware extracts and verifies stateless JWT from header or cookie
func AuthMiddleware(tm *jwt.TokenManager) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			tokenStr := extractToken(r)
			if tokenStr != "" {
				claims, err := tm.VerifyAccessToken(tokenStr)
				if err == nil && claims != nil {
					ctx := context.WithValue(r.Context(), UserClaimsContextKey, claims)
					r = r.WithContext(ctx)
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// RequireAuth ensures that request has valid authenticated claims
func RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := GetUserClaims(r.Context())
		if claims == nil {
			writeJSONError(w, http.StatusUnauthorized, "Authentication required")
			return
		}
		if claims.Status == domain.StatusSuspended {
			writeJSONError(w, http.StatusForbidden, "Account is suspended")
			return
		}
		next.ServeHTTP(w, r)
	})
}

// RequireRole ensures that user has one of the allowed roles
func RequireRole(roles ...domain.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := GetUserClaims(r.Context())
			if claims == nil {
				writeJSONError(w, http.StatusUnauthorized, "Authentication required")
				return
			}

			hasRole := false
			for _, role := range roles {
				if claims.Role == role || claims.Role == domain.RoleSuperAdmin {
					hasRole = true
					break
				}
			}

			if !hasRole {
				writeJSONError(w, http.StatusForbidden, "Insufficient permissions")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// GetUserClaims retrieves claims from context
func GetUserClaims(ctx context.Context) *jwt.UserClaims {
	claims, ok := ctx.Value(UserClaimsContextKey).(*jwt.UserClaims)
	if !ok {
		return nil
	}
	return claims
}

func extractToken(r *http.Request) string {
	// 1. Authorization header: Bearer <token>
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(authHeader, "Bearer ") {
		return strings.TrimPrefix(authHeader, "Bearer ")
	}

	// 2. Cookie fallback: authkit_access_token
	cookie, err := r.Cookie("authkit_access_token")
	if err == nil && cookie != nil && cookie.Value != "" {
		return cookie.Value
	}

	return ""
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error":   msg,
		"status":  status,
		"success": false,
	})
}
