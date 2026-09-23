package cli

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"authkit/internal/api"
	"authkit/internal/config"
	"authkit/internal/db/factory"
	"authkit/internal/email"
	"authkit/internal/jwt"
	"authkit/internal/mcp"
	"authkit/internal/oauth"
	"authkit/internal/service"
	"authkit/internal/web"
)

// RunServe initializes all subsystems and starts the AuthKit HTTP server
func RunServe(cfg *config.Config) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	log.Printf("[AUTHKIT] Initializing storage engine (%s)...", cfg.Database.Type)
	database, err := factory.NewDatabase(ctx, cfg.Database)
	if err != nil {
		return fmt.Errorf("database initialization failed: %w", err)
	}
	defer database.Close()
	log.Printf("[AUTHKIT] Database connected and migrated successfully.")

	// Token Manager
	tm, err := jwt.NewTokenManager(jwt.Config{
		Issuer:           cfg.JWT.Issuer,
		AccessExpiry:     cfg.JWT.AccessExpiry,
		RefreshExpiry:    cfg.JWT.RefreshExpiry,
		SigningAlgorithm: cfg.JWT.Algorithm,
		RSAPrivateKeyPEM: cfg.JWT.PrivateKeyPEM,
		RSAPublicKeyPEM:  cfg.JWT.PublicKeyPEM,
		HMACSecret:       cfg.JWT.HMACSecret,
		KeyID:            cfg.JWT.KeyID,
	})
	if err != nil {
		return fmt.Errorf("token manager initialization failed: %w", err)
	}
	log.Printf("[AUTHKIT] Token engine initialized with algorithm %s.", cfg.JWT.Algorithm)

	// Schema & Email Services
	schemaService := service.NewSchemaService(cfg.Schema)
	baseEmailService, err := email.NewEmailService(cfg.Email, "AuthKit")
	if err != nil {
		return fmt.Errorf("email service initialization failed: %w", err)
	}
	emailService := email.NewDynamicService(baseEmailService, "AuthKit")
	log.Printf("[AUTHKIT] Email notification service initialized with provider '%s'.", cfg.Email.Provider)

	// OAuth Providers
	oauthManager := oauth.NewManager()
	if cfg.OAuth.Google.Enabled && cfg.OAuth.Google.ClientID != "" {
		oauthManager.Register(oauth.NewGoogleProvider(cfg.OAuth.Google))
		log.Printf("[AUTHKIT] Google OAuth provider registered.")
	}
	if cfg.OAuth.GitHub.Enabled && cfg.OAuth.GitHub.ClientID != "" {
		oauthManager.Register(oauth.NewGitHubProvider(cfg.OAuth.GitHub))
		log.Printf("[AUTHKIT] GitHub OAuth provider registered.")
	}
	if cfg.OAuth.Firebase.Enabled && cfg.OAuth.Firebase.ProjectID != "" {
		oauthManager.Register(oauth.NewFirebaseProvider(cfg.OAuth.Firebase))
		log.Printf("[AUTHKIT] Firebase Auth integration registered (Project: %s).", cfg.OAuth.Firebase.ProjectID)
	}

	// Core Services
	authService := service.NewAuthService(cfg, database, tm, schemaService, emailService)
	userService := service.NewUserService(database, schemaService)
	oauthService := service.NewOAuthService(cfg, database, tm, oauthManager)

	// MCP Handler
	mcpHandler := mcp.NewHandler(userService, authService, tm, database, cfg)
	if cfg.MCP.Enabled {
		log.Printf("[AUTHKIT] Model Context Protocol (MCP) AI server enabled at /mcp.")
	}

	// Embedded static web UI
	staticFS, err := web.GetStaticFS()
	if err != nil {
		log.Printf("[AUTHKIT] Warning: could not load embedded web static assets: %v", err)
	}

	// HTTP Router
	router := api.NewRouter(api.RouterParams{
		Config:        cfg,
		Database:      database,
		TokenManager:  tm,
		AuthService:   authService,
		UserService:   userService,
		OAuthService:  oauthService,
		OAuthManager:  oauthManager,
		EmailService:  emailService,
		SchemaService: schemaService,
		MCPHandler:    mcpHandler,
		WebStaticFS:   staticFS,
		ConfigPath:    "authkit.yaml",
	})

	serverAddr := fmt.Sprintf("%s:%d", cfg.Server.Host, cfg.Server.Port)
	srv := &http.Server{
		Addr:         serverAddr,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Graceful shutdown channel
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("=====================================================")
		log.Printf(" [AUTHKIT] Service listening on http://%s", serverAddr)
		log.Printf(" • Documentation:  %s/docs.html", cfg.Server.BaseURL)
		log.Printf(" • Admin Console:  %s/admin.html", cfg.Server.BaseURL)
		log.Printf(" • JWKS Discovery: %s/.well-known/jwks.json", cfg.Server.BaseURL)
		log.Printf(" • Health Check:   %s/health", cfg.Server.BaseURL)
		log.Printf("=====================================================")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[AUTHKIT] Server failed: %v", err)
		}
	}()

	<-stopChan
	log.Println("[AUTHKIT] Shutting down gracefully...")

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer shutdownCancel()

	return srv.Shutdown(shutdownCtx)
}
