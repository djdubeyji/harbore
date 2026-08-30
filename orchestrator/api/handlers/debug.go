package handlers

import (
	"net/http"
	"strconv"

	"harbore.dev/orchestrator/db"
	"harbore.dev/orchestrator/logbuffer"
	"harbore.dev/orchestrator/models"
)

// DebugHandler backs the TEMPORARY debug console. It exposes recent orchestrator
// logs (from an in-memory buffer) and job records (from the database) so that
// operators can diagnose why modules may be producing no findings.
//
// All routes require a valid JWT (wired under the authenticated group) and are
// only registered when cfg.DebugConsole is true.
type DebugHandler struct {
	db  *db.DB
	buf *logbuffer.Buffer
}

func NewDebugHandler(database *db.DB, buf *logbuffer.Buffer) *DebugHandler {
	return &DebugHandler{db: database, buf: buf}
}

// Logs returns filtered log entries plus the distinct sources and per-level
// counts (for populating the console's filter controls).
//
// GET /api/v1/debug/logs?level=&source=&q=&since=&limit=
func (h *DebugHandler) Logs(w http.ResponseWriter, r *http.Request) {
	if h.buf == nil {
		jsonResponse(w, map[string]any{
			"entries": []any{},
			"sources": []string{},
			"counts":  map[string]int{},
			"enabled": false,
		}, http.StatusOK)
		return
	}

	qp := r.URL.Query()
	entries := h.buf.Query(logbuffer.Query{
		Level:  qp.Get("level"),
		Source: qp.Get("source"),
		Search: qp.Get("q"),
		Since:  parseInt64(qp.Get("since"), 0),
		Limit:  parseIntParam(qp.Get("limit"), 500),
	})

	jsonResponse(w, map[string]any{
		"entries": entries,
		"sources": h.buf.Sources(),
		"counts":  h.buf.Counts(),
		"enabled": true,
	}, http.StatusOK)
}

// Jobs returns recent job records across all scans, with counts by status.
//
// GET /api/v1/debug/jobs?status=&scan_id=&limit=
func (h *DebugHandler) Jobs(w http.ResponseWriter, r *http.Request) {
	qp := r.URL.Query()

	jobs, err := h.db.ListRecentJobs(
		r.Context(),
		qp.Get("status"),
		qp.Get("scan_id"),
		parseIntParam(qp.Get("limit"), 200),
	)
	if err != nil {
		jsonError(w, "failed to list jobs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	counts, err := h.db.CountJobsByStatus(r.Context())
	if err != nil {
		jsonError(w, "failed to count jobs: "+err.Error(), http.StatusInternalServerError)
		return
	}

	if jobs == nil {
		jobs = []*models.Job{}
	}
	jsonResponse(w, map[string]any{
		"jobs":   jobs,
		"counts": counts,
	}, http.StatusOK)
}

// ─── Small query-param helpers ────────────────────────────────────────────────

func parseIntParam(s string, fallback int) int {
	if s == "" {
		return fallback
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return fallback
	}
	return n
}

func parseInt64(s string, fallback int64) int64 {
	if s == "" {
		return fallback
	}
	n, err := strconv.ParseInt(s, 10, 64)
	if err != nil {
		return fallback
	}
	return n
}
