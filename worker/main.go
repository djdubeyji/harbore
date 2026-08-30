package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
	"harbore.dev/worker/modules"
	"harbore.dev/worker/modules/asset"
	"harbore.dev/worker/modules/auth"
	"harbore.dev/worker/modules/cert"
	"harbore.dev/worker/modules/compliance"
	"harbore.dev/worker/modules/crawler"
	"harbore.dev/worker/modules/fuzzer"
	"harbore.dev/worker/modules/passive"
	"harbore.dev/worker/modules/pci"
	"harbore.dev/worker/modules/vuln"
)

const (
	QueueJobs = "harbore:jobs:queue"
)

// WorkerJob mirrors the orchestrator payload
type WorkerJob struct {
	ID          uuid.UUID         `json:"id"`
	ScanID      uuid.UUID         `json:"scan_id"`
	Target      string            `json:"target"`
	Module      string            `json:"module"`
	Attempt     int               `json:"attempt"`
	MaxAttempts int               `json:"max_attempts"`
	Auth        modules.AuthConfig `json:"auth"`
	Config      map[string]any    `json:"config"`
}

// WorkerResult mirrors the orchestrator callback type
type WorkerResult struct {
	JobID    uuid.UUID                `json:"job_id"`
	ScanID   uuid.UUID                `json:"scan_id"`
	Status   string                   `json:"status"`
	Findings []modules.Finding        `json:"findings"`
	Error    string                   `json:"error"`
}

func main() {
	orchestratorURL := requireEnv("ORCHESTRATOR_URL")
	workerToken     := requireEnv("WORKER_TOKEN")
	redisAddr       := getEnv("REDIS_ADDR", "redis:6379")
	redisPassword   := getEnv("REDIS_PASSWORD", "")

	// ─── Module registry ──────────────────────────────────────────────────────
	registry := map[string]modules.ScanModule{
		"asset":      asset.New(),
		"cert":       cert.New(),
		"vuln":       vuln.New(),
		"crawler":    crawler.New(),
		"auth":       auth.New(),
		"fuzzer":     fuzzer.New(),
		"pci":        pci.New(),
		"passive":    passive.New(),
		"compliance": compliance.New(),
	}

	log.Printf("[worker] registered modules: %v", moduleNames(registry))

	// ─── Redis client ─────────────────────────────────────────────────────────
	rdb := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       0,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := rdb.Ping(ctx).Err(); err != nil {
		log.Fatalf("[worker] redis connection failed: %v", err)
	}
	log.Printf("[worker] connected to redis at %s", redisAddr)

	// ─── Graceful shutdown ────────────────────────────────────────────────────
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-quit
		log.Println("[worker] shutdown signal received")
		cancel()
	}()

	// ─── Main polling loop ────────────────────────────────────────────────────
	log.Println("[worker] polling job queue...")

	httpClient := &http.Client{Timeout: 30 * time.Second}

	for {
		select {
		case <-ctx.Done():
			log.Println("[worker] shutting down")
			return
		default:
		}

		// Block-pop from queue with 5s timeout
		result, err := rdb.BRPop(ctx, 5*time.Second, QueueJobs).Result()
		if err != nil {
			if err == redis.Nil || err == context.DeadlineExceeded {
				continue // timeout — no jobs, loop again
			}
			if ctx.Err() != nil {
				return // context cancelled
			}
			log.Printf("[worker] queue pop error: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}

		// result[0] = queue name, result[1] = payload
		if len(result) < 2 {
			continue
		}

		var job WorkerJob
		if err := json.Unmarshal([]byte(result[1]), &job); err != nil {
			log.Printf("[worker] failed to parse job: %v", err)
			continue
		}

		log.Printf("[worker] executing job=%s module=%s target=%s attempt=%d",
			job.ID, job.Module, job.Target, job.Attempt)

		// Execute the module
		workerResult := executeJob(ctx, job, registry)

		// POST results back to orchestrator
		if err := postResults(ctx, httpClient, orchestratorURL, workerToken, workerResult); err != nil {
			log.Printf("[worker] failed to post results for job=%s: %v", job.ID, err)
			// Re-queue with error if we can't report back
			workerResult.Status = "failed"
			workerResult.Error = fmt.Sprintf("result delivery failed: %v", err)
			// Try once more
			_ = postResults(ctx, httpClient, orchestratorURL, workerToken, workerResult)
		}
	}
}

func executeJob(ctx context.Context, job WorkerJob, registry map[string]modules.ScanModule) WorkerResult {
	result := WorkerResult{
		JobID:  job.ID,
		ScanID: job.ScanID,
	}

	mod, ok := registry[job.Module]
	if !ok {
		result.Status = "failed"
		result.Error = fmt.Sprintf("unknown module: %s", job.Module)
		log.Printf("[worker] unknown module: %s", job.Module)
		return result
	}

	// Per-job timeout: heavier modules get more time
	timeout := moduleTimeout(job.Module)
	jobCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Ensure the target is an absolute URL. For schemeless input we also probe
	// reachability and fall back to http for http-only hosts, so modules don't
	// silently produce zero findings against an unreachable https guess.
	target := modules.NormalizeTarget(job.Target)
	if !modules.HasScheme(job.Target) {
		target = modules.ResolveScheme(jobCtx, target)
	}
	if target != job.Target {
		log.Printf("[worker] job=%s normalized target %q -> %q", job.ID, job.Target, target)
	}

	modJob := &modules.Job{
		ID:          job.ID.String(),
		ScanID:      job.ScanID.String(),
		Target:      target,
		Module:      job.Module,
		Attempt:     job.Attempt,
		MaxAttempts: job.MaxAttempts,
		Auth:        job.Auth,
		Config:      job.Config,
	}

	findings, err := mod.Run(jobCtx, modJob)
	if err != nil {
		result.Status = "failed"
		result.Error = err.Error()
		log.Printf("[worker] job=%s module=%s error: %v", job.ID, job.Module, err)
		return result
	}

	result.Status = "completed"
	result.Findings = findings
	log.Printf("[worker] job=%s module=%s findings=%d", job.ID, job.Module, len(findings))
	return result
}

func postResults(ctx context.Context, client *http.Client, orchestratorURL, workerToken string, result WorkerResult) error {
	data, err := json.Marshal(result)
	if err != nil {
		return fmt.Errorf("marshal result: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		orchestratorURL+"/internal/results", bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Worker-Token", workerToken)

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("orchestrator returned HTTP %d", resp.StatusCode)
	}

	return nil
}

func moduleTimeout(module string) time.Duration {
	switch module {
	case "fuzzer":
		return 10 * time.Minute
	case "vuln", "auth":
		return 5 * time.Minute
	case "asset", "crawler":
		return 3 * time.Minute
	default:
		return 2 * time.Minute
	}
}

func moduleNames(registry map[string]modules.ScanModule) []string {
	names := make([]string, 0, len(registry))
	for k := range registry {
		names = append(names, k)
	}
	return names
}

func requireEnv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("required environment variable %s is not set", key)
	}
	return v
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
