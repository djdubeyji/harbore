package modules

import (
	"context"
	"time"
)

// ScanModule is the interface every scanning module must implement.
// Each module receives a job and returns findings.
type ScanModule interface {
	// Name returns the module identifier (must match models.Module* constants).
	Name() string

	// Run executes the scan against the target and returns findings.
	Run(ctx context.Context, job *Job) ([]Finding, error)
}

// Job is the per-module execution context (subset of WorkerJob).
type Job struct {
	ID          string
	ScanID      string
	Target      string
	Module      string
	Attempt     int
	MaxAttempts int
	Auth        AuthConfig
	Config      map[string]any
}

type AuthConfig struct {
	Headers map[string]string `json:"headers"`
	Cookies map[string]string `json:"cookies"`
	Bearer  string            `json:"bearer"`
	UserA   AuthUser          `json:"user_a"`
	UserB   AuthUser          `json:"user_b"`
}

type AuthUser struct {
	Username string            `json:"username"`
	Password string            `json:"password"`
	Headers  map[string]string `json:"headers"`
}

// Finding is a single security issue found by a module.
type Finding struct {
	Module         string    `json:"module"`
	Title          string    `json:"title"`
	Description    string    `json:"description"`
	Severity       Severity  `json:"severity"`
	CVSSScore      *float64  `json:"cvss_score"`
	CVSSVector     string    `json:"cvss_vector"`
	Endpoint       string    `json:"endpoint"`
	Method         string    `json:"method"`
	Request        string    `json:"request"`
	Response       string    `json:"response"`
	OWASPRef       string    `json:"owasp_ref"`
	PCIRequirement string    `json:"pci_requirement"`
	CWEID          string    `json:"cwe_id"`
	CreatedAt      time.Time `json:"created_at"`
}

type Severity string

const (
	Critical Severity = "critical"
	High     Severity = "high"
	Medium   Severity = "medium"
	Low      Severity = "low"
	Info     Severity = "info"
)

// CVSSScore helper
func CVSSPtr(score float64) *float64 {
	return &score
}

// ConfigString safely extracts a string value from module config.
func (j *Job) ConfigString(key, fallback string) string {
	if j.Config == nil {
		return fallback
	}
	if v, ok := j.Config[key]; ok {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return fallback
}

// ConfigBool safely extracts a bool value from module config.
func (j *Job) ConfigBool(key string, fallback bool) bool {
	if j.Config == nil {
		return fallback
	}
	if v, ok := j.Config[key]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	return fallback
}

// ConfigInt safely extracts an int value from module config.
func (j *Job) ConfigInt(key string, fallback int) int {
	if j.Config == nil {
		return fallback
	}
	if v, ok := j.Config[key]; ok {
		switch n := v.(type) {
		case int:
			return n
		case float64:
			return int(n)
		}
	}
	return fallback
}
