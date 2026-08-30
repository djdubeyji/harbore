package handlers

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"harbore.dev/orchestrator/api/middleware"
	"harbore.dev/orchestrator/db"
	"harbore.dev/orchestrator/models"
)

type AssetHandler struct {
	db *db.DB
}

func NewAssetHandler(database *db.DB) *AssetHandler {
	return &AssetHandler{db: database}
}

// requireOrg resolves the active org from X-Org-Id and verifies membership.
func requireOrg(w http.ResponseWriter, r *http.Request, database *db.DB) (uuid.UUID, bool) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return uuid.Nil, false
	}
	orgID, ok := activeOrgID(r)
	if !ok {
		jsonError(w, "missing or invalid X-Org-Id header", http.StatusBadRequest)
		return uuid.Nil, false
	}
	if member, err := database.IsOrgMember(r.Context(), userID, orgID); err != nil || !member {
		jsonError(w, "forbidden", http.StatusForbidden)
		return uuid.Nil, false
	}
	return orgID, true
}

func subnetOf(ip string) string {
	parts := strings.Split(ip, ".")
	if len(parts) == 4 {
		return parts[0] + "." + parts[1] + "." + parts[2] + ".0/24"
	}
	return ""
}

// Import ingests the agent's scan JSON and upserts assets for the active org.
func (h *AssetHandler) Import(w http.ResponseWriter, r *http.Request) {
	orgID, ok := requireOrg(w, r, h.db)
	if !ok {
		return
	}
	var payload struct {
		Hosts []struct {
			IP        string          `json:"ip_address"`
			Hostname  *string         `json:"hostname"`
			MAC       *string         `json:"mac_address"`
			Vendor    *string         `json:"vendor"`
			IsScanner bool            `json:"is_scanner"`
			Ports     json.RawMessage `json:"ports"`
		} `json:"hosts"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		jsonError(w, "invalid JSON — expected agent output with a \"hosts\" array", http.StatusBadRequest)
		return
	}
	if len(payload.Hosts) == 0 {
		jsonError(w, "no hosts in payload", http.StatusBadRequest)
		return
	}
	deref := func(p *string) string {
		if p == nil {
			return ""
		}
		return *p
	}
	imported := 0
	for _, host := range payload.Hosts {
		if host.IP == "" {
			continue
		}
		a := &models.Asset{
			OrgID:     orgID,
			IP:        host.IP,
			Hostname:  deref(host.Hostname),
			MAC:       deref(host.MAC),
			Vendor:    deref(host.Vendor),
			Subnet:    subnetOf(host.IP),
			Ports:     host.Ports,
			IsScanner: host.IsScanner,
			Source:    "agent",
		}
		if err := h.db.UpsertAsset(r.Context(), a); err != nil {
			jsonError(w, "failed to store assets", http.StatusInternalServerError)
			return
		}
		imported++
	}
	assets, _ := h.db.ListAssets(r.Context(), orgID)
	if assets == nil {
		assets = []*models.Asset{}
	}
	jsonResponse(w, map[string]interface{}{"imported": imported, "assets": assets}, http.StatusOK)
}

func (h *AssetHandler) List(w http.ResponseWriter, r *http.Request) {
	orgID, ok := requireOrg(w, r, h.db)
	if !ok {
		return
	}
	assets, err := h.db.ListAssets(r.Context(), orgID)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if assets == nil {
		assets = []*models.Asset{}
	}
	jsonResponse(w, assets, http.StatusOK)
}

func (h *AssetHandler) Update(w http.ResponseWriter, r *http.Request) {
	orgID, ok := requireOrg(w, r, h.db)
	if !ok {
		return
	}
	id, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid id", http.StatusBadRequest)
		return
	}
	var req struct {
		Label          string `json:"label"`
		Owner          string `json:"owner"`
		Criticality    string `json:"criticality"`
		Classification string `json:"classification"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if err := h.db.UpdateAssetCMDB(r.Context(), id, orgID, req.Label, req.Owner, req.Criticality, req.Classification); err != nil {
		jsonError(w, "failed to update asset", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]string{"message": "updated"}, http.StatusOK)
}

func (h *AssetHandler) Clear(w http.ResponseWriter, r *http.Request) {
	orgID, ok := requireOrg(w, r, h.db)
	if !ok {
		return
	}
	if err := h.db.ClearAssets(r.Context(), orgID); err != nil {
		jsonError(w, "failed to clear assets", http.StatusInternalServerError)
		return
	}
	jsonResponse(w, map[string]string{"message": "cleared"}, http.StatusOK)
}
