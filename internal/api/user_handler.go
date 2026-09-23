package api

import (
	"encoding/json"
	"net/http"
	"strconv"

	"authkit/internal/db"
	"authkit/internal/domain"
	"authkit/internal/service"
	"github.com/go-chi/chi/v5"
)

type UserHandler struct {
	userService *service.UserService
}

func NewUserHandler(userService *service.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

// List returns paginated user list
func (h *UserHandler) List(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("page_size"))

	var role *domain.Role
	if rStr := q.Get("role"); rStr != "" {
		ro := domain.Role(rStr)
		role = &ro
	}

	var status *domain.UserStatus
	if sStr := q.Get("status"); sStr != "" {
		st := domain.UserStatus(sStr)
		status = &st
	}

	filter := db.UserFilter{
		Query:     q.Get("query"),
		Role:      role,
		Status:    status,
		Page:      page,
		PageSize:  pageSize,
		SortBy:    q.Get("sort_by"),
		SortOrder: q.Get("sort_order"),
	}

	users, total, err := h.userService.ListUsers(r.Context(), filter)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"users":     users,
		"total":     total,
		"page":      page,
		"page_size": pageSize,
	})
}

// GetByID returns user profile by ID
func (h *UserHandler) GetByID(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	user, err := h.userService.GetUser(r.Context(), id)
	if err != nil {
		writeJSONError(w, http.StatusNotFound, "User not found")
		return
	}
	writeJSONResponse(w, http.StatusOK, user)
}

// Create provisions a user
func (h *UserHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req service.CreateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	user, err := h.userService.CreateUser(r.Context(), req)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSONResponse(w, http.StatusCreated, user)
}

// Update modifies user properties
func (h *UserHandler) Update(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var req service.UpdateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONError(w, http.StatusBadRequest, "Invalid JSON body")
		return
	}

	user, err := h.userService.UpdateUser(r.Context(), id, req)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, user)
}

// Delete removes a user
func (h *UserHandler) Delete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := h.userService.DeleteUser(r.Context(), id); err != nil {
		writeJSONError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSONResponse(w, http.StatusOK, map[string]interface{}{
		"success": true,
		"message": "User deleted successfully",
	})
}
