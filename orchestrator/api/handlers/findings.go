package handlers

import (
	"encoding/json"
	"log"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"harbore.dev/orchestrator/api/middleware"
	"harbore.dev/orchestrator/db"
	"harbore.dev/orchestrator/models"
	"harbore.dev/orchestrator/queue"
	"harbore.dev/orchestrator/scheduler"
	ws "harbore.dev/orchestrator/websocket"
)

type FindingHandler struct {
	db        *db.DB
	queue     *queue.Queue
	scheduler *scheduler.Scheduler
	hub       *ws.Hub
}

func NewFindingHandler(database *db.DB, q *queue.Queue, sched *scheduler.Scheduler, hub *ws.Hub) *FindingHandler {
	return &FindingHandler{db: database, queue: q, scheduler: sched, hub: hub}
}

// ListFindings returns all findings for a scan, ordered by severity.
func (h *FindingHandler) ListFindings(w http.ResponseWriter, r *http.Request) {
	scanID, err := uuid.Parse(chi.URLParam(r, "id"))
	if err != nil {
		jsonError(w, "invalid scan id", http.StatusBadRequest)
		return
	}

	// Enforce per-org isolation: the scan must belong to an org the caller is in.
	scan, err := h.db.GetScan(r.Context(), scanID)
	if err != nil || scan == nil {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}
	userID, ok := middleware.GetUserID(r.Context())
	if !ok {
		jsonError(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if member, _ := h.db.IsOrgMember(r.Context(), userID, scan.OrgID); !member {
		jsonError(w, "scan not found", http.StatusNotFound)
		return
	}

	findings, err := h.db.ListFindings(r.Context(), scanID)
	if err != nil {
		jsonError(w, "internal error", http.StatusInternalServerError)
		return
	}

	// Include finding stats
	stats, _ := h.db.GetScanFindingStats(r.Context(), scanID)
	failures, _ := h.db.ListFailures(r.Context(), scanID)

	jsonResponse(w, map[string]any{
		"findings": findings,
		"stats":    stats,
		"failures": failures,
		"total":    len(findings),
	}, http.StatusOK)
}

// MarkFalsePositive marks a finding as a false positive.
func (h *FindingHandler) MarkFalsePositive(w http.ResponseWriter, r *http.Request) {
	// TODO: implement
	jsonResponse(w, map[string]string{"message": "updated"}, http.StatusOK)
}

// WorkerCallback is called by worker containers to report results.
// This is an INTERNAL endpoint protected by the worker token.
func (h *FindingHandler) WorkerCallback(w http.ResponseWriter, r *http.Request) {
	var result models.WorkerResult
	if err := json.NewDecoder(r.Body).Decode(&result); err != nil {
		jsonError(w, "invalid result payload", http.StatusBadRequest)
		return
	}

	ctx := r.Context()

	// Update job status in DB
	switch result.Status {
	case models.JobCompleted:
		if err := h.db.UpdateJobStatus(ctx, result.JobID, models.JobCompleted, ""); err != nil {
			log.Printf("[callback] warn: update job status: %v", err)
		}

	case models.JobFailed:
		// Try to retry
		retried, err := h.scheduler.HandleRetry(ctx, &result)
		if err != nil {
			log.Printf("[callback] retry error job=%s: %v", result.JobID, err)
		}
		if !retried {
			if err := h.db.UpdateJobStatus(ctx, result.JobID, models.JobFailed, result.Error); err != nil {
				log.Printf("[callback] warn: update failed job: %v", err)
			}
		}
	}

	// Store findings
	storedCount := 0
	for i := range result.Findings {
		f := &result.Findings[i]
		jid := result.JobID
		if err := h.db.CreateFinding(ctx, result.ScanID, &jid, f); err != nil {
			log.Printf("[callback] warn: store finding: %v", err)
			continue
		}
		storedCount++

		// Broadcast new finding event
		h.hub.Broadcast(result.ScanID.String(), &models.WSEvent{
			Type:   models.WSEventFindingNew,
			ScanID: result.ScanID.String(),
			Payload: map[string]any{
				"title":    f.Title,
				"severity": f.Severity,
				"module":   f.Module,
				"endpoint": f.Endpoint,
			},
		})
	}

	// Decrement active job counter and check if scan is complete
	remaining, err := h.queue.DecrActiveScanJobs(ctx, result.ScanID.String())
	if err != nil {
		log.Printf("[callback] warn: decr active jobs: %v", err)
	}

	// Update scan progress in DB
	scan, _ := h.db.GetScan(ctx, result.ScanID)
	if scan != nil {
		completed := scan.CompletedJobs
		failed := scan.FailedJobs
		if result.Status == models.JobCompleted {
			completed++
		} else if result.Status == models.JobFailed {
			failed++
		}

		_ = h.db.UpdateScanProgress(ctx, result.ScanID, scan.TotalJobs, completed, failed)

		// Broadcast progress
		var pct float64
		if scan.TotalJobs > 0 {
			pct = float64(completed+failed) / float64(scan.TotalJobs) * 100
		}
		h.hub.Broadcast(result.ScanID.String(), &models.WSEvent{
			Type:   models.WSEventProgress,
			ScanID: result.ScanID.String(),
			Payload: models.ScanProgress{
				ScanID:        result.ScanID.String(),
				TotalJobs:     scan.TotalJobs,
				CompletedJobs: completed,
				FailedJobs:    failed,
				ProgressPct:   pct,
			},
		})
	}

	// If no more active jobs, mark scan as complete
	if remaining <= 0 {
		log.Printf("[callback] scan=%s all jobs complete — marking finished", result.ScanID)
		_ = h.db.UpdateScanStatus(ctx, result.ScanID, models.ScanCompleted)
		h.hub.Broadcast(result.ScanID.String(), &models.WSEvent{
			Type:   models.WSEventScanCompleted,
			ScanID: result.ScanID.String(),
			Payload: map[string]any{
				"findings_stored": storedCount,
			},
		})
	}

	log.Printf("[callback] job=%s scan=%s status=%s findings=%d remaining_jobs=%d",
		result.JobID, result.ScanID, result.Status, storedCount, remaining)

	jsonResponse(w, map[string]string{"status": "ok"}, http.StatusOK)
}

// ─── Shared helpers ───────────────────────────────────────────────────────────

func jsonResponse(w http.ResponseWriter, data any, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(data)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
