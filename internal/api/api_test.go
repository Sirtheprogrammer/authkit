package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"authkit/internal/config"
	"authkit/internal/db/sqlite"
	"authkit/internal/domain"
	"authkit/internal/email"
	"authkit/internal/jwt"
	"authkit/internal/mcp"
	"authkit/internal/oauth"
	"authkit/internal/service"
)

func setupTestServer(t *testing.T) (http.Handler, *jwt.TokenManager, func()) {
	tmpDB := "./test_api.db"
	database := sqlite.New(tmpDB)
	ctx := context.Background()

	if err := database.Connect(ctx); err != nil {
		t.Fatalf("Failed to connect test DB: %v", err)
	}
	if err := database.Migrate(ctx); err != nil {
		t.Fatalf("Failed to migrate test DB: %v", err)
	}

	cfg := config.DefaultConfig()
	cfg.Server.BaseURL = "http://localhost:8080"
	cfg.JWT.Algorithm = "RS256"

	tm, err := jwt.NewTokenManager(jwt.Config{
		Issuer:           "authkit-test",
		AccessExpiry:     15 * time.Minute,
		RefreshExpiry:    7 * 24 * time.Hour,
		SigningAlgorithm: "RS256",
		KeyID:            "test-key",
	})
	if err != nil {
		t.Fatalf("Failed to create token manager: %v", err)
	}

	schemaService := service.NewSchemaService(cfg.Schema)
	mockEmail := email.NewMockService(cfg.Email, "AuthKit")
	dynamicEmail := email.NewDynamicService(mockEmail, "AuthKit")
	oauthManager := oauth.NewManager()

	authService := service.NewAuthService(cfg, database, tm, schemaService, dynamicEmail)
	userService := service.NewUserService(database, schemaService)
	oauthService := service.NewOAuthService(cfg, database, tm, oauthManager)
	mcpHandler := mcp.NewHandler(userService, authService, tm, database, cfg)

	router := NewRouter(RouterParams{
		Config:        cfg,
		Database:      database,
		TokenManager:  tm,
		AuthService:   authService,
		UserService:   userService,
		OAuthService:  oauthService,
		OAuthManager:  oauthManager,
		EmailService:  dynamicEmail,
		SchemaService: schemaService,
		MCPHandler:    mcpHandler,
		WebStaticFS:   nil,
	})

	cleanup := func() {
		database.Close()
		os.Remove(tmpDB)
	}

	return router, tm, cleanup
}

func TestAuthFlowE2E(t *testing.T) {
	router, _, cleanup := setupTestServer(t)
	defer cleanup()

	// 1. Test Health Check
	reqHealth := httptest.NewRequest(http.MethodGet, "/health", nil)
	rrHealth := httptest.NewRecorder()
	router.ServeHTTP(rrHealth, reqHealth)
	if rrHealth.Code != http.StatusOK {
		t.Fatalf("Health check failed, got status %d", rrHealth.Code)
	}

	// 2. Test JWKS
	reqJWKS := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	rrJWKS := httptest.NewRecorder()
	router.ServeHTTP(rrJWKS, reqJWKS)
	if rrJWKS.Code != http.StatusOK {
		t.Fatalf("JWKS failed, got status %d", rrJWKS.Code)
	}

	// 3. Test Signup
	signupPayload := map[string]interface{}{
		"email":    "testuser@authkit.local",
		"password": "SuperPassword123!",
		"metadata": map[string]interface{}{
			"department": "Security",
			"tier":       "enterprise",
		},
	}
	body, _ := json.Marshal(signupPayload)
	reqSignup := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewBuffer(body))
	reqSignup.Header.Set("Content-Type", "application/json")
	rrSignup := httptest.NewRecorder()
	router.ServeHTTP(rrSignup, reqSignup)

	if rrSignup.Code != http.StatusCreated {
		t.Fatalf("Signup failed: %d - %s", rrSignup.Code, rrSignup.Body.String())
	}

	var authResp service.AuthResponse
	if err := json.Unmarshal(rrSignup.Body.Bytes(), &authResp); err != nil {
		t.Fatalf("Failed to parse signup response: %v", err)
	}

	if authResp.AccessToken == "" {
		t.Fatalf("Signup response missing access token")
	}
	if authResp.User.Email != "testuser@authkit.local" {
		t.Fatalf("Expected email testuser@authkit.local, got %s", authResp.User.Email)
	}

	// 4. Test Login
	loginPayload := map[string]interface{}{
		"email":    "testuser@authkit.local",
		"password": "SuperPassword123!",
	}
	bodyLogin, _ := json.Marshal(loginPayload)
	reqLogin := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewBuffer(bodyLogin))
	reqLogin.Header.Set("Content-Type", "application/json")
	rrLogin := httptest.NewRecorder()
	router.ServeHTTP(rrLogin, reqLogin)

	if rrLogin.Code != http.StatusOK {
		t.Fatalf("Login failed: %d - %s", rrLogin.Code, rrLogin.Body.String())
	}

	var loginResp service.AuthResponse
	_ = json.Unmarshal(rrLogin.Body.Bytes(), &loginResp)

	// 5. Test Get Me (/me) using stateless JWT Bearer header
	reqMe := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	reqMe.Header.Set("Authorization", "Bearer "+loginResp.AccessToken)
	rrMe := httptest.NewRecorder()
	router.ServeHTTP(rrMe, reqMe)

	if rrMe.Code != http.StatusOK {
		t.Fatalf("GetMe failed: %d - %s", rrMe.Code, rrMe.Body.String())
	}

	var meResp map[string]interface{}
	_ = json.Unmarshal(rrMe.Body.Bytes(), &meResp)
	if meResp["email"] != "testuser@authkit.local" {
		t.Fatalf("Expected testuser@authkit.local, got %v", meResp["email"])
	}

	// 6. Test Refresh Token
	refreshPayload := map[string]interface{}{
		"refresh_token": loginResp.RefreshToken,
	}
	bodyRefresh, _ := json.Marshal(refreshPayload)
	reqRefresh := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewBuffer(bodyRefresh))
	reqRefresh.Header.Set("Content-Type", "application/json")
	rrRefresh := httptest.NewRecorder()
	router.ServeHTTP(rrRefresh, reqRefresh)

	if rrRefresh.Code != http.StatusOK {
		t.Fatalf("Refresh token failed: %d - %s", rrRefresh.Code, rrRefresh.Body.String())
	}

	// 7. Test MCP Protocol (initialize and tools/list)
	mcpInitReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params":  map[string]interface{}{"protocolVersion": "2024-11-05"},
	}
	mcpBody, _ := json.Marshal(mcpInitReq)
	reqMCP := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(mcpBody))
	reqMCP.Header.Set("Content-Type", "application/json")
	rrMCP := httptest.NewRecorder()
	router.ServeHTTP(rrMCP, reqMCP)

	if rrMCP.Code != http.StatusOK {
		t.Fatalf("MCP initialize failed: %d - %s", rrMCP.Code, rrMCP.Body.String())
	}

	mcpListReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	}
	mcpListBody, _ := json.Marshal(mcpListReq)
	reqMCPList := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewBuffer(mcpListBody))
	reqMCPList.Header.Set("Content-Type", "application/json")
	rrMCPList := httptest.NewRecorder()
	router.ServeHTTP(rrMCPList, reqMCPList)

	if rrMCPList.Code != http.StatusOK {
		t.Fatalf("MCP tools/list failed: %d - %s", rrMCPList.Code, rrMCPList.Body.String())
	}
}

func TestAdminConfigEndpoints(t *testing.T) {
	router, tm, cleanup := setupTestServer(t)
	defer cleanup()
	defer os.Remove("authkit.yaml")

	// 1. Signup test user
	signupPayload := map[string]interface{}{
		"email":    "superadmin@authkit.local",
		"password": "Password123!",
	}
	body, _ := json.Marshal(signupPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/signup", bytes.NewBuffer(body))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, req)

	var signupResp map[string]interface{}
	json.Unmarshal(rr.Body.Bytes(), &signupResp)
	token := signupResp["access_token"].(string)

	// Create a superadmin token using server's token manager
	adminUser := &domain.User{
		ID:            "admin-id",
		Email:         "admin@authkit.local",
		Role:          domain.RoleSuperAdmin,
		Status:        domain.StatusActive,
		EmailVerified: true,
	}
	adminToken, _, _ := tm.GenerateAccessToken(adminUser, "test-session")

	// 2. Test GET /api/v1/admin/config
	reqGet := httptest.NewRequest(http.MethodGet, "/api/v1/admin/config", nil)
	reqGet.Header.Set("Authorization", "Bearer "+adminToken)
	rrGet := httptest.NewRecorder()
	router.ServeHTTP(rrGet, reqGet)

	if rrGet.Code != http.StatusOK {
		t.Fatalf("GET /api/v1/admin/config failed: %d - %s", rrGet.Code, rrGet.Body.String())
	}

	// 3. Test PUT /api/v1/admin/config (Configure GitHub OAuth and Remote SMTP)
	ghEnabled := true
	ghClientID := "gh_test_client_id_123"
	ghSecret := "gh_test_secret_456"
	smtpHost := "smtp.mailgun.org"
	smtpPort := 587
	smtpUser := "postmaster@mailgun.org"
	smtpPass := "supersecret"

	updatePayload := map[string]interface{}{
		"oauth": map[string]interface{}{
			"github": map[string]interface{}{
				"enabled":       &ghEnabled,
				"client_id":     &ghClientID,
				"client_secret": &ghSecret,
			},
		},
		"email": map[string]interface{}{
			"provider": "mock",
			"smtp": map[string]interface{}{
				"host":     &smtpHost,
				"port":     &smtpPort,
				"username": &smtpUser,
				"password": &smtpPass,
			},
		},
	}
	updBody, _ := json.Marshal(updatePayload)
	reqPut := httptest.NewRequest(http.MethodPut, "/api/v1/admin/config", bytes.NewBuffer(updBody))
	reqPut.Header.Set("Authorization", "Bearer "+adminToken)
	reqPut.Header.Set("Content-Type", "application/json")
	rrPut := httptest.NewRecorder()
	router.ServeHTTP(rrPut, reqPut)

	if rrPut.Code != http.StatusOK {
		t.Fatalf("PUT /api/v1/admin/config failed: %d - %s", rrPut.Code, rrPut.Body.String())
	}

	// 4. Test POST /api/v1/admin/config/test-email
	testEmailPayload := map[string]interface{}{
		"to_email": "tester@example.com",
	}
	emailBody, _ := json.Marshal(testEmailPayload)
	reqEmail := httptest.NewRequest(http.MethodPost, "/api/v1/admin/config/test-email", bytes.NewBuffer(emailBody))
	reqEmail.Header.Set("Authorization", "Bearer "+adminToken)
	reqEmail.Header.Set("Content-Type", "application/json")
	rrEmail := httptest.NewRecorder()
	router.ServeHTTP(rrEmail, reqEmail)

	if rrEmail.Code != http.StatusOK {
		t.Fatalf("POST /api/v1/admin/config/test-email failed: %d - %s", rrEmail.Code, rrEmail.Body.String())
	}
	_ = token
}

