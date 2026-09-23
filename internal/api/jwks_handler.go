package api

import (
	"encoding/json"
	"net/http"

	"authkit/internal/config"
	"authkit/internal/db"
	"authkit/internal/jwt"
)

type WellKnownHandler struct {
	cfg          *config.Config
	tokenManager *jwt.TokenManager
	database     db.Database
}

func NewWellKnownHandler(cfg *config.Config, tm *jwt.TokenManager, db db.Database) *WellKnownHandler {
	return &WellKnownHandler{
		cfg:          cfg,
		tokenManager: tm,
		database:     db,
	}
}

// JWKS returns the RFC 7517 JSON Web Key Set for stateless signature verification
func (h *WellKnownHandler) JWKS(w http.ResponseWriter, r *http.Request) {
	jwks := h.tokenManager.GetJWKS()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(jwks)
}

// OpenIDConfiguration returns standard OIDC discovery metadata
func (h *WellKnownHandler) OpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	baseURL := h.cfg.Server.BaseURL
	if baseURL == "" {
		proto := "http"
		if r.TLS != nil {
			proto = "https"
		}
		baseURL = proto + "://" + r.Host
	}

	configDoc := h.tokenManager.GetOpenIDConfiguration(baseURL)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "public, max-age=3600")
	_ = json.NewEncoder(w).Encode(configDoc)
}

// HealthCheck verifies service operational status
func (h *WellKnownHandler) HealthCheck(w http.ResponseWriter, r *http.Request) {
	status := "healthy"
	dbStatus := "connected"

	if err := h.database.Ping(r.Context()); err != nil {
		status = "degraded"
		dbStatus = "error: " + err.Error()
	}

	w.Header().Set("Content-Type", "application/json")
	if status == "healthy" {
		w.WriteHeader(http.StatusOK)
	} else {
		w.WriteHeader(http.StatusServiceUnavailable)
	}

	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"status":        status,
		"database":      dbStatus,
		"database_type": h.database.Type(),
		"jwt_algorithm": h.cfg.JWT.Algorithm,
		"version":       "1.0.0",
	})
}
