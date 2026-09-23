package api

import (
	"io/fs"
	"net/http"
	"strings"

	"authkit/internal/config"
	"authkit/internal/db"
	"authkit/internal/domain"
	"authkit/internal/jwt"
	"authkit/internal/mcp"
	"authkit/internal/oauth"
	"authkit/internal/service"
	"github.com/go-chi/chi/v5"
	chiMiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
)

type RouterParams struct {
	Config        *config.Config
	Database      db.Database
	TokenManager  *jwt.TokenManager
	AuthService   *service.AuthService
	UserService   *service.UserService
	OAuthService  *service.OAuthService
	OAuthManager  *oauth.Manager
	MCPHandler    *mcp.Handler
	WebStaticFS   fs.FS
}

// NewRouter constructs the complete Chi HTTP router with security middlewares
func NewRouter(p RouterParams) http.Handler {
	r := chi.NewRouter()

	// Base middleware stack
	r.Use(chiMiddleware.RequestID)
	r.Use(chiMiddleware.RealIP)
	r.Use(chiMiddleware.Recoverer)
	r.Use(chiMiddleware.Compress(5))

	// CORS configuration
	allowedOrigins := p.Config.Server.AllowedOrigins
	if len(allowedOrigins) == 0 {
		allowedOrigins = []string{"*"}
	}

	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   allowedOrigins,
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"Link", "Set-Cookie"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// Stateless token parsing middleware
	r.Use(AuthMiddleware(p.TokenManager))

	// Handlers
	authHandler := NewAuthHandler(p.AuthService)
	userHandler := NewUserHandler(p.UserService)
	oauthHandler := NewOAuthHandler(p.Config, p.OAuthService, p.OAuthManager)
	wellKnownHandler := NewWellKnownHandler(p.Config, p.TokenManager, p.Database)
	mcpServer := mcp.NewServer(p.MCPHandler)

	// Well-known & health endpoints (stateless RFC verification)
	r.Get("/.well-known/jwks.json", wellKnownHandler.JWKS)
	r.Get("/.well-known/openid-configuration", wellKnownHandler.OpenIDConfiguration)
	r.Get("/health", wellKnownHandler.HealthCheck)
	r.Get("/ready", wellKnownHandler.HealthCheck)

	// MCP JSON-RPC 2.0 endpoint for AI agents
	if p.Config.MCP.Enabled {
		r.Post("/mcp", mcpServer.ServeHTTP)
		r.Post("/api/v1/mcp", mcpServer.ServeHTTP)
	}

	// API Routes
	r.Route("/api/v1", func(api chi.Router) {
		// Authentication & Session
		api.Route("/auth", func(auth chi.Router) {
			auth.Post("/signup", authHandler.Signup)
			auth.Post("/login", authHandler.Login)
			auth.Post("/refresh", authHandler.Refresh)
			auth.Post("/logout", authHandler.Logout)

			auth.Post("/password/forgot", authHandler.ForgotPassword)
			auth.Post("/password/reset", authHandler.ResetPassword)

			auth.Post("/verify-email/confirm", authHandler.ConfirmEmail)
			auth.Post("/verify-email/resend", authHandler.ResendVerification)

			// Authenticated user self-service
			auth.With(RequireAuth).Get("/me", authHandler.GetMe)
			auth.With(RequireAuth).Put("/me", authHandler.UpdateMe)

			// OAuth & Federated identity
			auth.Get("/oauth/providers", oauthHandler.ListProviders)
			auth.Get("/oauth/{provider}", oauthHandler.Authorize)
			auth.Get("/oauth/{provider}/callback", oauthHandler.Callback)
			auth.Post("/firebase/verify", oauthHandler.VerifyFirebaseToken)
		})

		// Administrative User Management
		api.Route("/users", func(users chi.Router) {
			users.Use(RequireRole(domain.RoleAdmin, domain.RoleSuperAdmin))
			users.Get("/", userHandler.List)
			users.Post("/", userHandler.Create)
			users.Get("/{id}", userHandler.GetByID)
			users.Put("/{id}", userHandler.Update)
			users.Delete("/{id}", userHandler.Delete)
		})
	})

	// Static web assets (Landing Page, Documentation, and Admin UI)
	if p.WebStaticFS != nil {
		fileServer := http.FileServer(http.FS(p.WebStaticFS))
		r.NotFound(func(w http.ResponseWriter, req *http.Request) {
			// If path starts with /api/, return 404 JSON
			if strings.HasPrefix(req.URL.Path, "/api/") {
				writeJSONError(w, http.StatusNotFound, "Endpoint not found")
				return
			}
			if req.URL.Path == "/docs" {
				req.URL.Path = "/docs.html"
			} else if req.URL.Path == "/admin" {
				req.URL.Path = "/admin.html"
			}
			// Otherwise serve web frontend
			fileServer.ServeHTTP(w, req)
		})
	}

	return r
}
