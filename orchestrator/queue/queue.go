package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
	"harbore.dev/orchestrator/models"
)

const (
	QueueJobs     = "harbore:jobs:queue"
	QueueRetry    = "harbore:jobs:retry"
	QueueResults  = "harbore:jobs:results"
	KeyScanActive = "harbore:scan:active:%s"   // scan ID → active job count
	KeyScanLock   = "harbore:scan:lock:%s"     // scan ID → lock
	TTLScanActive = 24 * time.Hour
)

type Queue struct {
	client *redis.Client
}

func New(addr, password string) (*Queue, error) {
	client := redis.NewClient(&redis.Options{
		Addr:         addr,
		Password:     password,
		DB:           0,
		DialTimeout:  5 * time.Second,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 10 * time.Second,
		PoolSize:     20,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := client.Ping(ctx).Err(); err != nil {
		return nil, fmt.Errorf("redis ping failed: %w", err)
	}

	return &Queue{client: client}, nil
}

func (q *Queue) Close() error {
	return q.client.Close()
}

// EnqueueJob pushes a job to the main queue (LPUSH for FIFO with BRPOP).
func (q *Queue) EnqueueJob(ctx context.Context, job *models.WorkerJob) error {
	data, err := json.Marshal(job)
	if err != nil {
		return fmt.Errorf("marshal job: %w", err)
	}
	return q.client.LPush(ctx, QueueJobs, data).Err()
}

// EnqueueJobs pushes multiple jobs atomically using a pipeline.
func (q *Queue) EnqueueJobs(ctx context.Context, jobs []*models.WorkerJob) error {
	pipe := q.client.Pipeline()
	for _, job := range jobs {
		data, err := json.Marshal(job)
		if err != nil {
			return fmt.Errorf("marshal job %s: %w", job.ID, err)
		}
		pipe.LPush(ctx, QueueJobs, data)
	}
	_, err := pipe.Exec(ctx)
	return err
}

// EnqueueRetry pushes a job to the retry queue with a delay.
func (q *Queue) EnqueueRetry(ctx context.Context, job *models.WorkerJob, delay time.Duration) error {
	data, err := json.Marshal(job)
	if err != nil {
		return err
	}
	score := float64(time.Now().Add(delay).Unix())
	return q.client.ZAdd(ctx, QueueRetry, redis.Z{
		Score:  score,
		Member: data,
	}).Err()
}

// ProcessRetryQueue moves eligible retry jobs back to the main queue.
// Call this periodically from a background goroutine.
func (q *Queue) ProcessRetryQueue(ctx context.Context) (int, error) {
	now := float64(time.Now().Unix())
	results, err := q.client.ZRangeByScoreWithScores(ctx, QueueRetry, &redis.ZRangeBy{
		Min:    "0",
		Max:    fmt.Sprintf("%f", now),
		Offset: 0,
		Count:  100,
	}).Result()
	if err != nil {
		return 0, err
	}

	moved := 0
	for _, r := range results {
		data := r.Member.(string)
		pipe := q.client.Pipeline()
		pipe.ZRem(ctx, QueueRetry, data)
		pipe.LPush(ctx, QueueJobs, data)
		if _, err := pipe.Exec(ctx); err == nil {
			moved++
		}
	}
	return moved, nil
}

// QueueLength returns the current job queue length.
func (q *Queue) QueueLength(ctx context.Context) (int64, error) {
	return q.client.LLen(ctx, QueueJobs).Result()
}

// SetActiveScanJobs tracks how many jobs are active for a scan.
func (q *Queue) IncrActiveScanJobs(ctx context.Context, scanID string) error {
	key := fmt.Sprintf(KeyScanActive, scanID)
	pipe := q.client.Pipeline()
	pipe.Incr(ctx, key)
	pipe.Expire(ctx, key, TTLScanActive)
	_, err := pipe.Exec(ctx)
	return err
}

func (q *Queue) DecrActiveScanJobs(ctx context.Context, scanID string) (int64, error) {
	key := fmt.Sprintf(KeyScanActive, scanID)
	return q.client.Decr(ctx, key).Result()
}

func (q *Queue) GetActiveScanJobs(ctx context.Context, scanID string) (int64, error) {
	key := fmt.Sprintf(KeyScanActive, scanID)
	v, err := q.client.Get(ctx, key).Int64()
	if err == redis.Nil {
		return 0, nil
	}
	return v, err
}

// PublishScanEvent publishes a WebSocket event for a scan.
func (q *Queue) PublishScanEvent(ctx context.Context, scanID string, event *models.WSEvent) error {
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	return q.client.Publish(ctx, "harbore:events:"+scanID, data).Err()
}

// SubscribeScanEvents subscribes to real-time events for all scans.
func (q *Queue) SubscribeScanEvents(ctx context.Context) *redis.PubSub {
	return q.client.PSubscribe(ctx, "harbore:events:*")
}

// SetScanLock prevents duplicate scan starts.
func (q *Queue) SetScanLock(ctx context.Context, scanID string) (bool, error) {
	key := fmt.Sprintf(KeyScanLock, scanID)
	return q.client.SetNX(ctx, key, 1, 5*time.Minute).Result()
}

func (q *Queue) ReleaseScanLock(ctx context.Context, scanID string) error {
	key := fmt.Sprintf(KeyScanLock, scanID)
	return q.client.Del(ctx, key).Err()
}
