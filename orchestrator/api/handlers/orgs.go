package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"harbore.dev/orchestrator/api/middleware"
	"harbore.dev/orchestrator/db"
	"harbore.dev/orchestrator/models"
)

type OrgHandler struct {
	db *db.DB
}

func NewOrgHandler(database *db.DB) *OrgHandler {
	return &OrgHandler{db: database}
}

// List returns the organizations the current user is a member of.
func (h *OrgHandler) List(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	orgs, err := h.db.ListOrgsForUser(r.Context(), userID)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if orgs == nil {
		orgs = []*models.Organization{}
	}
	jsonResponse(w, orgs, http.StatusOK)
}

// Create makes a new organization (the creator becomes its admin).
func (h *OrgHandler) Create(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}
	org, err := h.db.CreateOrg(r.Context(), req.Name, userID)
	if err != nil {
		jsonError(w, "failed to create organization", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, org, http.StatusCreated)
}

// AddMember adds a user (by email) to an organization the caller belongs to.
func (h *OrgHandler) AddMember(w http.ResponseWriter, r *http.Request) {
	orgID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid organization id", http.StatusBadRequest)
		return
	}
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	member, err := h.db.IsOrgMember(r.Context(), userID, orgID)
	if err != nil || !member {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}
	var req struct {
		Email string `json:"email"`
		Role  string `json:"role"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Email == "" {
		jsonError(w, "email is required", http.StatusBadRequest)
		return
	}
	if err := h.db.AddOrgMemberByEmail(r.Context(), orgID, req.Email, req.Role); err != nil {
		jsonError(w, err.Error(), http.StatusBadRequest)
		return
	}
	jsonResponse(w, map[string]string{"message": "member added"}, http.StatusOK)
}
