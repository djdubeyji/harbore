package api

import (
	"net/http"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"harbore.dev/orchestrator/api/handlers"
	"harbore.dev/orchestrator/api/middleware"
	"harbore.dev/orchestrator/config"
	"harbore.dev/orchestrator/db"
	"harbore.dev/orchestrator/logbuffer"
	"harbore.dev/orchestrator/models"
	"harbore.dev/orchestrator/queue"
	"harbore.dev/orchestrator/scheduler"
	ws "harbore.dev/orchestrator/websocket"
)

func NewRouter(
	cfg *config.Config,
	database *db.DB,
	q *queue.Queue,
	sched *scheduler.Scheduler,
	hub *ws.Hub,
	logBuf *logbuffer.Buffer,
) http.Handler {
	// Init JWT secret
	middleware.SetJWTSecret(cfg.JWTSecret)

	// Handlers
	authH := handlers.NewAuthHandler(database, cfg)
	scanH := handlers.NewScanHandler(database, q, sched, hub)
	findingH := handlers.NewFindingHandler(database, q, sched, hub)
	reportH := handlers.NewReportHandler(database, cfg)
	debugH := handlers.NewDebugHandler(database, logBuf)
	orgH := handlers.NewOrgHandler(database)
	tlsH := handlers.NewTLSHandler(database)
	assetH := handlers.NewAssetHandler(database)

	r := chi.NewRouter()

	// ─── Global middleware ────────────────────────────────────────────────────
	r.Use(chimw.RealIP)
	r.Use(chimw.RequestID)
	r.Use(chimw.Logger)
	r.Use(chimw.Recoverer)
	r.Use(chimw.CleanPath)
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"},
		AllowedMethods:   []string{"GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-Worker-Token", "X-Org-Id"},
		ExposedHeaders:   []string{"Link"},
		AllowCredentials: false,
		MaxAge:           300,
	}))

	// ─── Health check (no auth) ───────────────────────────────────────────────
	r.Get("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","service":"harbore-orchestrator"}`))
	})

	// ─── Auth routes (no JWT required) ───────────────────────────────────────
	r.Post("/api/v1/auth/login", authH.Login)

	// ─── Authenticated routes ─────────────────────────────────────────────────
	r.Group(func(r chi.Router) {
		r.Use(middleware.Auth)

		// Auth
		r.Get("/api/v1/auth/me", authH.Me)
		r.Post("/api/v1/auth/password", authH.ChangePassword)
		r.Put("/api/v1/auth/profile", authH.UpdateProfile)

		// Organizations (multi-tenancy)
		r.Get("/api/v1/orgs", orgH.List)
		r.Post("/api/v1/orgs", orgH.Create)
		r.Post("/api/v1/orgs/{id}/members", orgH.AddMember)

		// TLS certificate monitoring
		r.Post("/api/v1/tls/checks", tlsH.Check)
		r.Get("/api/v1/tls/checks", tlsH.List)
		r.Delete("/api/v1/tls/checks/{id}", tlsH.Delete)

		// Asset discovery (CMDB)
		r.Post("/api/v1/assets/import", assetH.Import)
		r.Get("/api/v1/assets", assetH.List)
		r.Patch("/api/v1/assets/{id}", assetH.Update)
		r.Delete("/api/v1/assets", assetH.Clear)

		// User management (admin only)
		r.Group(func(r chi.Router) {
			r.Use(middleware.RequireRole(models.RoleAdmin))
			r.Post("/api/v1/users", authH.Register)
		})

		// Projects
		r.Get("/api/v1/projects", func(w http.ResponseWriter, r *http.Request) {
			// TODO: implement project list handler
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`[]`))
		})

		// Scans
		r.Post("/api/v1/scans", scanH.CreateScan)
		r.Get("/api/v1/scans", scanH.ListScans)
		r.Get("/api/v1/scans/{id}", scanH.GetScan)
		r.Post("/api/v1/scans/{id}/start", scanH.StartScan)
		r.Post("/api/v1/scans/{id}/cancel", scanH.CancelScan)
		r.Post("/api/v1/scans/{id}/retest", scanH.RetestScan)
		r.Post("/api/v1/scans/{id}/reconcile", scanH.ReconcileRetest)
		r.Get("/api/v1/scans/{id}/progress", scanH.GetScanProgress)
		r.Get("/api/v1/scans/{id}/findings", findingH.ListFindings)
		r.Get("/api/v1/scans/{id}/report", reportH.GenerateReport)
		r.Post("/api/v1/scans/{id}/report/governance", reportH.GenerateGovernanceReport)

		// WebSocket (auth via query param since WS doesn't support headers easily)
		r.Get("/ws/scans/{id}", scanH.WSHandler)

		// Debug console (TEMPORARY) — set DEBUG_CONSOLE=false to disable.
		if cfg.DebugConsole {
			r.Get("/api/v1/debug/logs", debugH.Logs)
			r.Get("/api/v1/debug/jobs", debugH.Jobs)
		}
	})

	// ─── Internal worker callback (worker token auth) ─────────────────────────
	r.Group(func(r chi.Router) {
		r.Use(middleware.WorkerAuth(cfg.WorkerToken))
		r.Post("/internal/results", findingH.WorkerCallback)
	})

	return r
}
