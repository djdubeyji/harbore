package handlers

import (
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"harbore.dev/orchestrator/api/middleware"
	"harbore.dev/orchestrator/db"
	"harbore.dev/orchestrator/models"
	"harbore.dev/orchestrator/queue"
	"harbore.dev/orchestrator/scheduler"
	ws "harbore.dev/orchestrator/websocket"
)

type ScanHandler struct {
	db        *db.DB
	queue     *queue.Queue
	scheduler *scheduler.Scheduler
	hub       *ws.Hub
}

func NewScanHandler(database *db.DB, q *queue.Queue, sched *scheduler.Scheduler, hub *ws.Hub) *ScanHandler {
	return &ScanHandler{db: database, queue: q, scheduler: sched, hub: hub}
}

// canAccess reports whether the caller may access a scan (i.e. is a member of
// the scan's organization). Used to enforce per-org data isolation.
func (h *ScanHandler) canAccess(r *http.Request, scan *models.Scan) bool {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		return false
	}
	m, _ := h.db.IsOrgMember(r.Context(), userID, scan.OrgID)
	return m
}

// CreateScan creates a new scan (does NOT start it).
func (h *ScanHandler) CreateScan(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req models.CreateScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		jsonError(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		jsonError(w, "name is required", http.StatusBadRequest)
		return
	}
	if len(req.Config.Targets) == 0 {
		jsonError(w, "at least one target is required", http.StatusBadRequest)
		return
	}
	if len(req.Modules) == 0 {
		// Default to a safe passive scan if no modules specified
		req.Modules = []string{models.ModuleAsset, models.ModuleCert, models.ModuleCrawler}
	}

	orgID, ok := activeOrgID(r)
	if !ok {
		jsonError(w, "missing or invalid X-Org-Id header", http.StatusBadRequest)
		return
	}
	if member, err := h.db.IsOrgMember(r.Context(), userID, orgID); err != nil || !member {
		jsonError(w, "forbidden: not a member of this organization", http.StatusForbidden)
		return
	}

	scan, err := h.db.CreateScan(r.Context(), &req, userID, orgID)
	if err != nil {
		log.Printf("[scan] create error: %v", err)
		jsonError(w, "failed to create scan", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, scan, http.StatusCreated)
}

// StartScan begins executing a scan.
func (h *ScanHandler) StartScan(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid scan id", http.StatusBadRequest)
		return
	}

	scan, err := h.db.GetScan(r.Context(), scanID)
	if err != nil || scan == nil {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}
	if !h.canAccess(r, scan) {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}

	if scan.Status == models.ScanRunning {
		jsonError(w, "scan is already running", http.StatusConflict)
		return
	}
	if scan.Status == models.ScanCompleted {
		jsonError(w, "scan has already completed", http.StatusConflict)
		return
	}

	// Acquire lock to prevent double-start
	locked, err := h.queue.SetScanLock(r.Context(), scanID.String())
	if err != nil || !locked {
		jsonError(w, "scan is already starting", http.StatusConflict)
		return
	}

	// Build execution plan
	plan, err := h.scheduler.BuildPlan(r.Context(), scan)
	if err != nil {
		_ = h.queue.ReleaseScanLock(r.Context(), scanID.String())
		jsonError(w, "failed to build scan plan: "+err.Error(), http.StatusBadRequest)
		return
	}

	// Update scan status and job counts
	if err := h.db.UpdateScanStatus(r.Context(), scanID, models.ScanRunning); err != nil {
		jsonError(w, "failed to update scan status", http.StatusInternalServerError)
		return
	}
	if err := h.db.UpdateScanProgress(r.Context(), scanID, plan.TotalJobs, 0, 0); err != nil {
		log.Printf("[scan] warn: failed to update progress: %v", err)
	}

	// Dispatch jobs to Redis queue asynchronously
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		defer h.queue.ReleaseScanLock(ctx, scanID.String())

		if err := h.scheduler.Dispatch(ctx, plan); err != nil {
			log.Printf("[scan] dispatch error scan=%s: %v", scanID, err)
			_ = h.db.UpdateScanStatus(ctx, scanID, models.ScanFailed)
			return
		}

		h.hub.Broadcast(scanID.String(), &models.WSEvent{
			Type:   models.WSEventScanStarted,
			ScanID: scanID.String(),
			Payload: map[string]any{
				"total_jobs":     plan.TotalJobs,
				"num_containers": plan.NumContainers,
				"estimated_mins": plan.EstimatedMins,
			},
		})

		log.Printf("[scan] started scan=%s jobs=%d containers=%d est=%.1fmin",
			scanID, plan.TotalJobs, plan.NumContainers, plan.EstimatedMins)
	}()

	jsonResponse(w, map[string]any{
		"message":        "scan started",
		"scan_id":        scan.ID,
		"total_jobs":     plan.TotalJobs,
		"num_containers": plan.NumContainers,
		"estimated_mins": plan.EstimatedMins,
	}, http.StatusOK)
}

// GetScan returns scan details.
func (h *ScanHandler) GetScan(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid scan id", http.StatusBadRequest)
		return
	}

	scan, err := h.db.GetScan(r.Context(), scanID)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}
	if scan == nil {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}
	if !h.canAccess(r, scan) {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}

	jsonResponse(w, scan, http.StatusOK)
}

// ListScans returns all scans for a project.
func (h *ScanHandler) ListScans(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	orgID, ok := activeOrgID(r)
	if !ok {
		jsonError(w, "missing or invalid X-Org-Id header", http.StatusBadRequest)
		return
	}
	if member, err := h.db.IsOrgMember(r.Context(), userID, orgID); err != nil || !member {
		jsonError(w, "forbidden", http.StatusForbidden)
		return
	}

	scans, err := h.db.ListScans(r.Context(), orgID)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	jsonResponse(w, scans, http.StatusOK)
}

// CancelScan stops a running scan.
func (h *ScanHandler) CancelScan(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid scan id", http.StatusBadRequest)
		return
	}

	scan, err := h.db.GetScan(r.Context(), scanID)
	if err != nil || scan == nil {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}
	if !h.canAccess(r, scan) {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}

	if scan.Status != models.ScanRunning {
		jsonError(w, "scan is not running", http.StatusConflict)
		return
	}

	if err := h.db.UpdateScanStatus(r.Context(), scanID, models.ScanCancelled); err != nil {
		jsonError(w, "failed to cancel scan", http.StatusInternalServerError)
		return
	}

	h.hub.Broadcast(scanID.String(), &models.WSEvent{
		Type:    models.WSEventScanFailed,
		ScanID:  scanID.String(),
		Payload: map[string]string{"reason": "cancelled by user"},
	})

	jsonResponse(w, map[string]string{"message": "scan cancelled"}, http.StatusOK)
}

// GetScanProgress returns a lightweight progress snapshot.
func (h *ScanHandler) GetScanProgress(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid scan id", http.StatusBadRequest)
		return
	}

	scan, err := h.db.GetScan(r.Context(), scanID)
	if err != nil || scan == nil {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}
	if !h.canAccess(r, scan) {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}

	var pct float64
	if scan.TotalJobs > 0 {
		pct = float64(scan.CompletedJobs+scan.FailedJobs) / float64(scan.TotalJobs) * 100
	}

	jsonResponse(w, models.ScanProgress{
		ScanID:        scan.ID.String(),
		Status:        string(scan.Status),
		TotalJobs:     scan.TotalJobs,
		CompletedJobs: scan.CompletedJobs,
		FailedJobs:    scan.FailedJobs,
		ProgressPct:   pct,
	}, http.StatusOK)
}

// WSHandler upgrades the connection to WebSocket for live scan events.
func (h *ScanHandler) WSHandler(w http.ResponseWriter, r *http.Request) {
	scanID := chi.URLParam(r, "id")
	if _, err := uuid.Parse(scanID); err != nil {
		http.Error(w, "invalid scan id", http.StatusBadRequest)
		return
	}
	h.hub.Upgrade(w, r, scanID)
}

// ─── Retest ───────────────────────────────────────────────────────────────────

func retestKey(module, title, endpoint string) string {
	return strings.ToLower(strings.TrimSpace(module) + "|" + strings.TrimSpace(title) + "|" + strings.TrimSpace(endpoint))
}

// RetestScan clones a completed scan's configuration into a new scan, links it as
// a retest of the original, and launches it. The frontend later calls Reconcile.
func (h *ScanHandler) RetestScan(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid scan id", http.StatusBadRequest)
		return
	}
	orig, err := h.db.GetScan(r.Context(), scanID)
	if err != nil || orig == nil {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}
	if !h.canAccess(r, orig) {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}
	userID, _ := middleware.GetUserID(r.Context())

	req := &models.CreateScanRequest{
		ProjectID:      orig.ProjectID.String(),
		Name:           orig.Name + " (retest)",
		TargetType:     orig.TargetType,
		Config:         orig.Config,
		Modules:        orig.Modules,
		ContainerLimit: orig.ContainerLimit,
		MaxRetries:     orig.MaxRetries,
	}
	newScan, err := h.db.CreateScan(r.Context(), req, userID, orig.OrgID)
	if err != nil {
		jsonError(w, "failed to create retest scan: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Launch (mirrors StartScan's plan + dispatch)
	locked, err := h.queue.SetScanLock(r.Context(), newScan.ID.String())
	if err != nil || !locked {
		jsonError(w, "failed to acquire scan lock", http.StatusConflict)
		return
	}
	plan, err := h.scheduler.BuildPlan(r.Context(), newScan)
	if err != nil {
		_ = h.queue.ReleaseScanLock(r.Context(), newScan.ID.String())
		jsonError(w, "failed to build scan plan: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := h.db.UpdateScanStatus(r.Context(), newScan.ID, models.ScanRunning); err != nil {
		jsonError(w, "failed to update scan status", http.StatusInternalServerError)
		return
	}
	_ = h.db.UpdateScanProgress(r.Context(), newScan.ID, plan.TotalJobs, 0, 0)

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
		defer cancel()
		defer h.queue.ReleaseScanLock(ctx, newScan.ID.String())
		if err := h.scheduler.Dispatch(ctx, plan); err != nil {
			log.Printf("[retest] dispatch error scan=%s: %v", newScan.ID, err)
			_ = h.db.UpdateScanStatus(ctx, newScan.ID, models.ScanFailed)
			return
		}
		log.Printf("[retest] started scan=%s (retest of %s)", newScan.ID, scanID)
	}()

	jsonResponse(w, map[string]any{
		"message":        "retest started",
		"retest_scan_id": newScan.ID,
		"parent_scan_id": scanID,
		"total_jobs":     plan.TotalJobs,
	}, http.StatusOK)
}

// ReconcileRetest diffs a completed retest scan against its parent and marks each
// parent finding fixed (absent in retest) or still-open (present).
func (h *ScanHandler) ReconcileRetest(w http.ResponseWriter, r *http.Request) {
	parentID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid scan id", http.StatusBadRequest)
		return
	}
	parent, err := h.db.GetScan(r.Context(), parentID)
	if err != nil || parent == nil {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}
	if !h.canAccess(r, parent) {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}
	var body struct {
		RetestScanID string `json:"retest_scan_id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.RetestScanID == "" {
		jsonError(w, "retest_scan_id is required", http.StatusBadRequest)
		return
	}
	retestID, err := uuid.Parse(body.RetestScanID)
	if err != nil {
		jsonError(w, "invalid retest_scan_id", http.StatusBadRequest)
		return
	}
	retest, err := h.db.GetScan(r.Context(), retestID)
	if err != nil || retest == nil || !h.canAccess(r, retest) {
		jsonError(w, "retest scan not found", http.StatusNotFound)
		return
	}

	parentFindings, _ := h.db.ListFindings(r.Context(), parentID)
	retestFindings, _ := h.db.ListFindings(r.Context(), retestID)

	present := make(map[string]bool, len(retestFindings))
	for _, f := range retestFindings {
		if f.IsFalsePositive {
			continue
		}
		present[retestKey(f.Module, f.Title, f.Endpoint)] = true
	}

	now := time.Now()
	fixed, stillOpen := 0, 0
	for _, f := range parentFindings {
		if f.IsFalsePositive {
			continue
		}
		if present[retestKey(f.Module, f.Title, f.Endpoint)] {
			_ = h.db.SetFindingStatus(r.Context(), f.ID, "open", &now)
			stillOpen++
		} else {
			_ = h.db.SetFindingStatus(r.Context(), f.ID, "fixed", &now)
			fixed++
		}
	}

	jsonResponse(w, map[string]any{
		"parent_scan_id": parentID,
		"retest_scan_id": retestID,
		"fixed":          fixed,
		"still_open":     stillOpen,
	}, http.StatusOK)
}
