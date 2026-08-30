package handlers

import (
	"encoding/json"
	"net/http"

	"golang.org/x/crypto/bcrypt"
	"harbore.dev/orchestrator/api/middleware"
	"harbore.dev/orchestrator/config"
	"harbore.dev/orchestrator/db"
	"harbore.dev/orchestrator/models"
)

type AuthHandler struct {
	db  *db.DB
	cfg *config.Config
}

func NewAuthHandler(database *db.DB, cfg *config.Config) *AuthHandler {
	return &AuthHandler{db: database, cfg: cfg}
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" {
		jsonError(w, "email and password are required", http.StatusBadRequest)
		return
	}

	user, err := h.db.GetUserByEmail(r.Context(), req.Email)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if user == nil {
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		jsonError(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	token, err := middleware.GenerateToken(user.ID, user.Role, h.cfg.JWTSecret, h.cfg.JWTExpiryHours)
	if err != nil {
		jsonError(w, "failed to generate token", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, models.LoginResponse{Token: token, User: *user}, http.StatusOK)
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	// Only admins can create users via the API
	callerRole := middleware.GetUserRole(r.Context())
	if callerRole != models.RoleAdmin {
		jsonError(w, "only admins can create users", http.StatusForbidden)
		return
	}

	var req struct {
		Email    string          `json:"email"`
		Password string          `json:"password"`
		Name     string          `json:"name"`
		Role     models.UserRole `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Password == "" || req.Name == "" {
		jsonError(w, "email, password and name are required", http.StatusBadRequest)
		return
	}

	if len(req.Password) < 8 {
		jsonError(w, "password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	role := req.Role
	if role == "" {
		role = models.RoleAnalyst
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	user, err := h.db.CreateUser(r.Context(), req.Email, string(hash), req.Name, role)
	if err != nil {
		jsonError(w, "failed to create user (email may already exist)", http.StatusConflict)
		return
	}

	jsonResponse(w, user, http.StatusCreated)
}

func (h *AuthHandler) Me(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := h.db.GetUserByID(r.Context(), userID)
	if err != nil || user == nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	jsonResponse(w, user, http.StatusOK)
}

func (h *AuthHandler) ChangePassword(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req struct {
		CurrentPassword string `json:"current_password"`
		NewPassword     string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	user, err := h.db.GetUserByID(r.Context(), userID)
	if err != nil || user == nil {
		jsonError(w, "user not found", http.StatusNotFound)
		return
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.CurrentPassword)); err != nil {
		jsonError(w, "current password is incorrect", http.StatusUnauthorized)
		return
	}

	if len(req.NewPassword) < 8 {
		jsonError(w, "new password must be at least 8 characters", http.StatusBadRequest)
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if err := h.db.UpdateUserPassword(r.Context(), userID, string(hash)); err != nil {
		jsonError(w, "failed to update password", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, map[string]string{"message": "password updated"}, http.StatusOK)
}

// UpdateProfile updates the current user's display name and avatar.
func (h *AuthHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Name   string `json:"name"`
		Avatar string `json:"avatar"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}
	if len(req.Avatar) > 2_000_000 {
		jsonError(w, "avatar too large (max ~2MB)", http.StatusBadRequest)
		return
	}
	user, err := h.db.UpdateUserProfile(r.Context(), userID, req.Name, req.Avatar)
	if err != nil || user == nil {
		jsonError(w, "failed to update profile", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, user, http.StatusOK)
}
