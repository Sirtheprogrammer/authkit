package mcp

import (
	"context"
	"encoding/json"
	"fmt"

	"authkit/internal/config"
	"authkit/internal/db"
	"authkit/internal/domain"
	"authkit/internal/jwt"
	"authkit/internal/service"
)

// ToolDefinition defines an MCP tool schema
type ToolDefinition struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description"`
	InputSchema map[string]interface{} `json:"inputSchema"`
}

// Handler handles MCP tool invocations
type Handler struct {
	userService  *service.UserService
	authService  *service.AuthService
	tokenManager *jwt.TokenManager
	database     db.Database
	cfg          *config.Config
}

func NewHandler(
	userService *service.UserService,
	authService *service.AuthService,
	tm *jwt.TokenManager,
	database db.Database,
	cfg *config.Config,
) *Handler {
	return &Handler{
		userService:  userService,
		authService:  authService,
		tokenManager: tm,
		database:     database,
		cfg:          cfg,
	}
}

// GetTools returns the list of supported MCP tools
func (h *Handler) GetTools() []ToolDefinition {
	return []ToolDefinition{
		{
			Name:        "authkit_list_users",
			Description: "Search and list users with pagination, role, or status filters in AuthKit",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"query":     map[string]interface{}{"type": "string", "description": "Search term for email or custom metadata"},
					"role":      map[string]interface{}{"type": "string", "enum": []string{"user", "admin", "superadmin"}},
					"status":    map[string]interface{}{"type": "string", "enum": []string{"active", "pending", "suspended"}},
					"page":      map[string]interface{}{"type": "integer", "description": "Page number, default 1"},
					"page_size": map[string]interface{}{"type": "integer", "description": "Page size, default 20"},
				},
			},
		},
		{
			Name:        "authkit_get_user",
			Description: "Retrieve detailed profile, verification status, and dynamic custom schema metadata of a user",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"id":    map[string]interface{}{"type": "string", "description": "AuthKit User ID"},
					"email": map[string]interface{}{"type": "string", "description": "User Email address"},
				},
			},
		},
		{
			Name:        "authkit_create_user",
			Description: "Create a new user with optional role, password, and custom metadata fields",
			InputSchema: map[string]interface{}{
				"type": "object",
				"required": []string{"email"},
				"properties": map[string]interface{}{
					"email":          map[string]interface{}{"type": "string"},
					"password":       map[string]interface{}{"type": "string"},
					"role":           map[string]interface{}{"type": "string", "enum": []string{"user", "admin", "superadmin"}},
					"email_verified": map[string]interface{}{"type": "boolean"},
					"metadata":       map[string]interface{}{"type": "object", "description": "Custom schema attributes"},
				},
			},
		},
		{
			Name:        "authkit_update_user",
			Description: "Update user role, status, email verification, or custom metadata attributes",
			InputSchema: map[string]interface{}{
				"type": "object",
				"required": []string{"id"},
				"properties": map[string]interface{}{
					"id":             map[string]interface{}{"type": "string"},
					"role":           map[string]interface{}{"type": "string", "enum": []string{"user", "admin", "superadmin"}},
					"status":         map[string]interface{}{"type": "string", "enum": []string{"active", "pending", "suspended"}},
					"email_verified": map[string]interface{}{"type": "boolean"},
					"metadata":       map[string]interface{}{"type": "object"},
				},
			},
		},
		{
			Name:        "authkit_ban_user",
			Description: "Instantly suspend/ban a user and revoke all active sessions",
			InputSchema: map[string]interface{}{
				"type": "object",
				"required": []string{"id"},
				"properties": map[string]interface{}{
					"id":        map[string]interface{}{"type": "string"},
					"suspended": map[string]interface{}{"type": "boolean", "description": "true to suspend, false to reactivate"},
				},
			},
		},
		{
			Name:        "authkit_delete_user",
			Description: "Permanently delete a user account and purge sessions",
			InputSchema: map[string]interface{}{
				"type": "object",
				"required": []string{"id"},
				"properties": map[string]interface{}{
					"id": map[string]interface{}{"type": "string"},
				},
			},
		},
		{
			Name:        "authkit_inspect_token",
			Description: "Statelessly decode, verify, and inspect claims inside an AuthKit JWT access token",
			InputSchema: map[string]interface{}{
				"type": "object",
				"required": []string{"token"},
				"properties": map[string]interface{}{
					"token": map[string]interface{}{"type": "string", "description": "JWT Access Token string"},
				},
			},
		},
		{
			Name:        "authkit_send_password_reset",
			Description: "Trigger password reset flow for a user",
			InputSchema: map[string]interface{}{
				"type": "object",
				"required": []string{"email"},
				"properties": map[string]interface{}{
					"email": map[string]interface{}{"type": "string"},
				},
			},
		},
		{
			Name:        "authkit_get_system_stats",
			Description: "Retrieve AuthKit system status, total user count, and storage engine",
			InputSchema: map[string]interface{}{
				"type": "object",
			},
		},
	}
}

// CallTool executes the given tool by name with arguments
func (h *Handler) CallTool(ctx context.Context, name string, args map[string]interface{}) (interface{}, error) {
	switch name {
	case "authkit_list_users":
		var filter db.UserFilter
		if q, ok := args["query"].(string); ok {
			filter.Query = q
		}
		if r, ok := args["role"].(string); ok {
			role := domain.Role(r)
			filter.Role = &role
		}
		if s, ok := args["status"].(string); ok {
			status := domain.UserStatus(s)
			filter.Status = &status
		}
		if p, ok := args["page"].(float64); ok {
			filter.Page = int(p)
		}
		if ps, ok := args["page_size"].(float64); ok {
			filter.PageSize = int(ps)
		}
		users, total, err := h.userService.ListUsers(ctx, filter)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"users": users,
			"total": total,
		}, nil

	case "authkit_get_user":
		if id, ok := args["id"].(string); ok && id != "" {
			return h.userService.GetUser(ctx, id)
		}
		if email, ok := args["email"].(string); ok && email != "" {
			u, err := h.database.GetUserByEmail(ctx, email)
			if err != nil {
				return nil, err
			}
			return u.ToPublic(), nil
		}
		return nil, fmt.Errorf("either 'id' or 'email' parameter is required")

	case "authkit_create_user":
		email, _ := args["email"].(string)
		password, _ := args["password"].(string)
		r, _ := args["role"].(string)
		verified, _ := args["email_verified"].(bool)
		meta, _ := args["metadata"].(map[string]interface{})

		req := service.CreateUserRequest{
			Email:         email,
			Password:      password,
			Role:          domain.Role(r),
			EmailVerified: verified,
			Metadata:      meta,
		}
		return h.userService.CreateUser(ctx, req)

	case "authkit_update_user":
		id, _ := args["id"].(string)
		if id == "" {
			return nil, fmt.Errorf("id is required")
		}
		req := service.UpdateUserRequest{}
		if r, ok := args["role"].(string); ok {
			role := domain.Role(r)
			req.Role = &role
		}
		if s, ok := args["status"].(string); ok {
			status := domain.UserStatus(s)
			req.Status = &status
		}
		if ev, ok := args["email_verified"].(bool); ok {
			req.EmailVerified = &ev
		}
		if m, ok := args["metadata"].(map[string]interface{}); ok {
			req.Metadata = m
		}
		return h.userService.UpdateUser(ctx, id, req)

	case "authkit_ban_user":
		id, _ := args["id"].(string)
		if id == "" {
			return nil, fmt.Errorf("id is required")
		}
		suspended, _ := args["suspended"].(bool)
		status := domain.StatusActive
		if suspended {
			status = domain.StatusSuspended
		}
		return h.userService.UpdateUser(ctx, id, service.UpdateUserRequest{Status: &status})

	case "authkit_delete_user":
		id, _ := args["id"].(string)
		if id == "" {
			return nil, fmt.Errorf("id is required")
		}
		err := h.userService.DeleteUser(ctx, id)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"success": true, "deleted_id": id}, nil

	case "authkit_inspect_token":
		tokenStr, _ := args["token"].(string)
		if tokenStr == "" {
			return nil, fmt.Errorf("token string is required")
		}
		claims, err := h.tokenManager.VerifyAccessToken(tokenStr)
		if err != nil {
			return map[string]interface{}{"valid": false, "error": err.Error()}, nil
		}
		return map[string]interface{}{
			"valid":          true,
			"user_id":        claims.UserID,
			"email":          claims.Email,
			"role":           claims.Role,
			"status":         claims.Status,
			"email_verified": claims.EmailVerified,
			"metadata":       claims.Metadata,
			"issuer":         claims.Issuer,
			"expires_at":     claims.ExpiresAt.Time,
		}, nil

	case "authkit_send_password_reset":
		email, _ := args["email"].(string)
		if email == "" {
			return nil, fmt.Errorf("email is required")
		}
		err := h.authService.ForgotPassword(ctx, email)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{"success": true, "message": "Password reset email dispatched"}, nil

	case "authkit_get_system_stats":
		count, err := h.userService.CountUsers(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]interface{}{
			"database_type": h.database.Type(),
			"total_users":   count,
			"jwt_algorithm": h.cfg.JWT.Algorithm,
			"email_provider": h.cfg.Email.Provider,
			"version":       "1.0.0",
			"status":        "operational",
		}, nil

	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

// FormatResult converts any value to JSON string for MCP text content
func FormatResult(val interface{}) string {
	b, err := json.MarshalIndent(val, "", "  ")
	if err != nil {
		return fmt.Sprintf("%v", val)
	}
	return string(b)
}
