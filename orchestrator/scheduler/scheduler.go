package scheduler

import (
	"context"
	"fmt"
	"log"
	"math"
	"time"

	"github.com/google/uuid"
	"harbore.dev/orchestrator/db"
	"harbore.dev/orchestrator/models"
	"harbore.dev/orchestrator/queue"
)

// taskWeight defines container cost per module.
// Higher = more resource-intensive = fewer APIs per container.
var taskWeight = map[string]int{
	models.ModuleAsset:      2,
	models.ModuleCert:       1,
	models.ModulePassive:    1,
	models.ModuleCrawler:    2,
	models.ModuleVuln:       5,
	models.ModuleAuth:       5,
	models.ModulePCI:        4,
	models.ModuleFuzzer:     10,
	models.ModuleCompliance: 2,
}

// apisPerContainer defines base APIs per container per module.
var apisPerContainer = map[string]int{
	models.ModuleAsset:      50,
	models.ModuleCert:       100,
	models.ModulePassive:    100,
	models.ModuleCrawler:    30,
	models.ModuleVuln:       20,
	models.ModuleAuth:       20,
	models.ModulePCI:        25,
	models.ModuleFuzzer:     10,
	models.ModuleCompliance: 40,
}

type Scheduler struct {
	db    *db.DB
	queue *queue.Queue

	maxSystemContainers int
	retryDelay          time.Duration
}

func New(database *db.DB, q *queue.Queue, maxSystemContainers int) *Scheduler {
	return &Scheduler{
		db:                  database,
		queue:               q,
		maxSystemContainers: maxSystemContainers,
		retryDelay:          10 * time.Second,
	}
}

// Plan represents the execution plan for a scan.
type Plan struct {
	ScanID         uuid.UUID
	TotalTargets   int
	TotalJobs      int
	NumContainers  int
	BatchSize      int
	EstimatedMins  float64
	Jobs           []*models.WorkerJob
}

// BuildPlan creates an execution plan for a scan.
// This decides: how many containers, batch sizes, and creates all job records.
func (s *Scheduler) BuildPlan(ctx context.Context, scan *models.Scan) (*Plan, error) {
	targets := scan.Config.Targets
	if len(targets) == 0 {
		return nil, fmt.Errorf("scan has no targets")
	}
	if len(scan.Modules) == 0 {
		return nil, fmt.Errorf("scan has no modules selected")
	}

	// Calculate effective container count
	numContainers := s.calculateContainerCount(scan)

	// Total jobs = targets × modules
	// Each target gets its own job per module for parallelism
	totalJobs := len(targets) * len(scan.Modules)

	// Batch size: distribute targets across containers per module
	batchSize := int(math.Ceil(float64(len(targets)) / float64(numContainers)))
	if batchSize < 1 {
		batchSize = 1
	}

	// Estimated time: based on heaviest module weight
	estimatedMins := s.estimateTime(len(targets), scan.Modules, numContainers)

	log.Printf("[scheduler] scan=%s targets=%d modules=%d containers=%d batch=%d est=%.1fmin",
		scan.ID, len(targets), len(scan.Modules), numContainers, batchSize, estimatedMins)

	// Create job records and worker payloads
	jobs := make([]*models.WorkerJob, 0, totalJobs)
	for _, module := range scan.Modules {
		for _, rawTarget := range targets {
			// Guarantee a scheme even for scans created before normalization
			// existed. Idempotent for already-normalized targets.
			target := models.NormalizeTarget(rawTarget)

			// Create DB job record
			j, err := s.db.CreateJob(ctx, scan.ID, target, module, scan.MaxRetries)
			if err != nil {
				return nil, fmt.Errorf("create job for %s/%s: %w", module, target, err)
			}

			// Create worker payload
			wj := &models.WorkerJob{
				ID:          j.ID,
				ScanID:      scan.ID,
				Target:      target,
				Module:      module,
				Attempt:     1,
				MaxAttempts: scan.MaxRetries,
				Auth:        scan.Config.Auth,
				Config:      scan.Config.ModuleConfig,
			}
			if wj.Config == nil {
				wj.Config = map[string]any{}
			}
			jobs = append(jobs, wj)
		}
	}

	return &Plan{
		ScanID:        scan.ID,
		TotalTargets:  len(targets),
		TotalJobs:     totalJobs,
		NumContainers: numContainers,
		BatchSize:     batchSize,
		EstimatedMins: estimatedMins,
		Jobs:          jobs,
	}, nil
}

// Dispatch pushes all jobs from a plan to the Redis queue.
func (s *Scheduler) Dispatch(ctx context.Context, plan *Plan) error {
	if err := s.queue.EnqueueJobs(ctx, plan.Jobs); err != nil {
		return fmt.Errorf("enqueue jobs: %w", err)
	}

	for range plan.Jobs {
		if err := s.queue.IncrActiveScanJobs(ctx, plan.ScanID.String()); err != nil {
			log.Printf("[scheduler] warn: failed to increment active job counter: %v", err)
		}
	}

	return nil
}

// HandleRetry determines if a failed job should be retried and re-queues it.
func (s *Scheduler) HandleRetry(ctx context.Context, result *models.WorkerResult) (bool, error) {
	job, err := s.db.GetJob(ctx, result.JobID)
	if err != nil || job == nil {
		return false, err
	}

	if job.Attempt >= job.MaxAttempts {
		// Max retries exceeded — log as permanent failure
		jid := result.JobID
		if err := s.db.CreateFailureLog(ctx, result.ScanID, &jid,
			job.Target, job.Module, job.Attempt, result.Error); err != nil {
			log.Printf("[scheduler] warn: failed to create failure log: %v", err)
		}
		return false, nil
	}

	// Increment attempt and re-queue with exponential backoff
	if err := s.db.IncrementJobAttempt(ctx, job.ID); err != nil {
		return false, err
	}

	delay := s.retryDelay * time.Duration(job.Attempt)
	wj := &models.WorkerJob{
		ID:          job.ID,
		ScanID:      job.ScanID,
		Target:      job.Target,
		Module:      job.Module,
		Attempt:     job.Attempt + 1,
		MaxAttempts: job.MaxAttempts,
	}

	if err := s.queue.EnqueueRetry(ctx, wj, delay); err != nil {
		return false, fmt.Errorf("enqueue retry: %w", err)
	}

	log.Printf("[scheduler] job=%s retry attempt=%d delay=%v", job.ID, job.Attempt+1, delay)
	return true, nil
}

// StartRetryWorker runs a background goroutine that processes the retry queue.
func (s *Scheduler) StartRetryWorker(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				n, err := s.queue.ProcessRetryQueue(ctx)
				if err != nil {
					log.Printf("[scheduler] retry queue error: %v", err)
				} else if n > 0 {
					log.Printf("[scheduler] moved %d retry jobs back to main queue", n)
				}
			}
		}
	}()
}

// ─── Private helpers ──────────────────────────────────────────────────────────

// calculateContainerCount decides how many containers to use.
// It respects: user limit, system limit, and task weight.
func (s *Scheduler) calculateContainerCount(scan *models.Scan) int {
	userLimit := scan.ContainerLimit
	if userLimit <= 0 {
		userLimit = s.maxSystemContainers
	}

	// Cap at system maximum
	effective := min(userLimit, s.maxSystemContainers)

	// Scale down based on average task weight of selected modules
	avgWeight := s.averageWeight(scan.Modules)
	if avgWeight >= 8 {
		// Heavy fuzzing/interactive — reduce containers for stability
		effective = max(1, effective/2)
	}

	// No more containers than we have targets
	if len(scan.Config.Targets) < effective {
		effective = len(scan.Config.Targets)
	}

	return max(1, effective)
}

func (s *Scheduler) averageWeight(modules []string) float64 {
	if len(modules) == 0 {
		return 1
	}
	total := 0
	for _, m := range modules {
		if w, ok := taskWeight[m]; ok {
			total += w
		} else {
			total += 3
		}
	}
	return float64(total) / float64(len(modules))
}

func (s *Scheduler) estimateTime(numTargets int, modules []string, numContainers int) float64 {
	// Find the heaviest module (bottleneck)
	maxSecsPerAPI := 30.0 // default
	for _, m := range modules {
		w, ok := taskWeight[m]
		if !ok {
			w = 3
		}
		secs := float64(w) * 10.0
		if secs > maxSecsPerAPI {
			maxSecsPerAPI = secs
		}
	}

	targetsPerContainer := math.Ceil(float64(numTargets) / float64(numContainers))
	totalSecs := targetsPerContainer * maxSecsPerAPI
	return math.Ceil(totalSecs / 60.0)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
