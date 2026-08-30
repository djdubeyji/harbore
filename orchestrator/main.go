package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"harbore.dev/orchestrator/api"
	"harbore.dev/orchestrator/config"
	"harbore.dev/orchestrator/container"
	"harbore.dev/orchestrator/db"
	"harbore.dev/orchestrator/logbuffer"
	"harbore.dev/orchestrator/queue"
	"harbore.dev/orchestrator/scheduler"
	ws "harbore.dev/orchestrator/websocket"
)

func main() {
	// Load .env in development
	_ = godotenv.Load()

	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("[main] config error: %v", err)
	}

	// TEMPORARY debug console: tee standard log output into an in-memory ring
	// buffer so the console can display recent logs. Disable with DEBUG_CONSOLE=false.
	var logBuf *logbuffer.Buffer
	if cfg.DebugConsole {
		logBuf = logbuffer.New(2000)
		log.SetOutput(io.MultiWriter(os.Stderr, logBuf))
		log.Println("[main] debug console enabled (DEBUG_CONSOLE=true) — log capture active")
	}

	log.Printf("[main] starting Harbore orchestrator env=%s", cfg.Env)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// ─── Database ─────────────────────────────────────────────────────────────
	database, err := db.New(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("[main] database error: %v", err)
	}
	defer database.Close()
	log.Println("[main] database connected")

	// ─── Redis queue ──────────────────────────────────────────────────────────
	jobQueue, err := queue.New(cfg.RedisAddr, cfg.RedisPassword)
	if err != nil {
		log.Fatalf("[main] redis error: %v", err)
	}
	defer jobQueue.Close()
	log.Println("[main] redis connected")

	// ─── Container manager ────────────────────────────────────────────────────
	orchestratorURL := fmt.Sprintf("http://orchestrator:%s", cfg.Port)
	containerMgr, err := container.New(
		cfg.WorkerImage,
		cfg.DockerNetwork,
		cfg.WorkerToken,
		orchestratorURL,
	)
	if err != nil {
		log.Printf("[main] warn: docker not available: %v", err)
		// Non-fatal — orchestrator can still queue jobs
	} else {
		log.Println("[main] docker connected")
		_ = containerMgr // used by future container-spawning logic
	}

	// ─── Scheduler ────────────────────────────────────────────────────────────
	sched := scheduler.New(database, jobQueue, cfg.DefaultMaxContainers)
	sched.StartRetryWorker(ctx)
	log.Println("[main] scheduler started")

	// ─── WebSocket hub ────────────────────────────────────────────────────────
	hub := ws.NewHub()
	log.Println("[main] websocket hub started")

	// ─── HTTP server ──────────────────────────────────────────────────────────
	router := api.NewRouter(cfg, database, jobQueue, sched, hub, logBuf)

	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in goroutine
	go func() {
		log.Printf("[main] listening on :%s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[main] server error: %v", err)
		}
	}()

	// ─── Graceful shutdown ────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("[main] shutdown signal received")
	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[main] shutdown error: %v", err)
	}

	log.Println("[main] Harbore orchestrator stopped")
}
