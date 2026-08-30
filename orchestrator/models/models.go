package models

import (
	"encoding/json"
	"time"

	"github.com/google/uuid"
)

// ─── Enums ────────────────────────────────────────────────────────────────────

type UserRole string

const (
	RoleAdmin   UserRole = "admin"
	RoleAnalyst UserRole = "analyst"
	RoleViewer  UserRole = "viewer"
)

type ScanStatus string

const (
	ScanPending   ScanStatus = "pending"
	ScanRunning   ScanStatus = "running"
	ScanCompleted ScanStatus = "completed"
	ScanFailed    ScanStatus = "failed"
	ScanCancelled ScanStatus = "cancelled"
)

type JobStatus string

const (
	JobQueued    JobStatus = "queued"
	JobRunning   JobStatus = "running"
	JobCompleted JobStatus = "completed"
	JobFailed    JobStatus = "failed"
	JobRetrying  JobStatus = "retrying"
)

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

type TargetType string

const (
	TargetOpenAPI   TargetType = "openapi"
	TargetPostman   TargetType = "postman"
	TargetGraphQL   TargetType = "graphql"
	TargetSOAP      TargetType = "soap"
	TargetURLList   TargetType = "url_list"
	TargetHAR       TargetType = "har"
	TargetMCP       TargetType = "mcp"
	TargetSingleURL TargetType = "single_url"
)

// ─── Module names ─────────────────────────────────────────────────────────────

const (
	ModuleAsset      = "asset"
	ModuleCert       = "cert"
	ModuleVuln       = "vuln"
	ModuleCrawler    = "crawler"
	ModuleAuth       = "auth"
	ModuleFuzzer     = "fuzzer"
	ModulePCI        = "pci"
	ModulePassive    = "passive"
	ModuleCompliance = "compliance"
)

// ─── User ─────────────────────────────────────────────────────────────────────

type User struct {
	ID           uuid.UUID `json:"id" db:"id"`
	Email        string    `json:"email" db:"email"`
	PasswordHash string    `json:"-" db:"password_hash"`
	Name         string    `json:"name" db:"name"`
	Role         UserRole  `json:"role" db:"role"`
	IsActive     bool      `json:"is_active" db:"is_active"`
	Avatar       string    `json:"avatar" db:"avatar"`
	CreatedAt    time.Time `json:"created_at" db:"created_at"`
	UpdatedAt    time.Time `json:"updated_at" db:"updated_at"`
}

// ─── Project ──────────────────────────────────────────────────────────────────

type Asset struct {
	ID             uuid.UUID       `json:"id" db:"id"`
	OrgID          uuid.UUID       `json:"org_id" db:"org_id"`
	IP             string          `json:"ip_address" db:"ip"`
	Hostname       string          `json:"hostname" db:"hostname"`
	MAC            string          `json:"mac_address" db:"mac"`
	Vendor         string          `json:"vendor" db:"vendor"`
	Subnet         string          `json:"subnet" db:"subnet"`
	Ports          json.RawMessage `json:"ports" db:"ports"`
	IsScanner      bool            `json:"is_scanner" db:"is_scanner"`
	Label          string          `json:"label" db:"label"`
	Owner          string          `json:"owner" db:"owner"`
	Criticality    string          `json:"criticality" db:"criticality"`
	Classification string          `json:"classification" db:"classification"`
	Source         string          `json:"source" db:"source"`
	DiscoveredAt   time.Time       `json:"discovered_at" db:"discovered_at"`
	UpdatedAt      time.Time       `json:"updated_at" db:"updated_at"`
}

type Certificate struct {
	ID            uuid.UUID  `json:"id" db:"id"`
	OrgID         uuid.UUID  `json:"org_id" db:"org_id"`
	Host          string     `json:"host" db:"host"`
	Port          int        `json:"port" db:"port"`
	CommonName    string     `json:"common_name" db:"common_name"`
	Issuer        string     `json:"issuer" db:"issuer"`
	SANs          []string   `json:"sans" db:"sans"`
	NotBefore     *time.Time `json:"not_before" db:"not_before"`
	NotAfter      *time.Time `json:"not_after" db:"not_after"`
	KeyType       string     `json:"key_type" db:"key_type"`
	KeyBits       int        `json:"key_bits" db:"key_bits"`
	SigAlg        string     `json:"sig_alg" db:"sig_alg"`
	TLSVersion    string     `json:"tls_version" db:"tls_version"`
	Error         string     `json:"error" db:"error"`
	LastCheckedAt time.Time  `json:"last_checked_at" db:"last_checked_at"`
	CreatedAt     time.Time  `json:"created_at" db:"created_at"`
}

type Organization struct {
	ID        uuid.UUID `json:"id" db:"id"`
	Name      string    `json:"name" db:"name"`
	Role      string    `json:"role,omitempty" db:"role"` // caller's role in this org (list queries)
	CreatedAt time.Time `json:"created_at" db:"created_at"`
}

type Project struct {
	ID          uuid.UUID `json:"id" db:"id"`
	OwnerID     uuid.UUID `json:"owner_id" db:"owner_id"`
	Name        string    `json:"name" db:"name"`
	Description string    `json:"description" db:"description"`
	CreatedAt   time.Time `json:"created_at" db:"created_at"`
	UpdatedAt   time.Time `json:"updated_at" db:"updated_at"`
}

// ─── Scan ─────────────────────────────────────────────────────────────────────

type ScanConfig struct {
	// Input targets
	Targets []string `json:"targets"` // URLs, spec file paths, etc.

	// Authentication
	Auth AuthConfig `json:"auth"`

	// Module-specific configs
	NucleiEnabled bool           `json:"nuclei_enabled"`
	ModuleConfig  map[string]any `json:"module_config"`
}

type AuthConfig struct {
	Headers map[string]string `json:"headers"`
	Cookies map[string]string `json:"cookies"`
	Bearer  string            `json:"bearer"`

	// Multi-user auth for AuthZ testing
	UserA AuthUser `json:"user_a"`
	UserB AuthUser `json:"user_b"`
}

type AuthUser struct {
	Username string            `json:"username"`
	Password string            `json:"password"`
	Headers  map[string]string `json:"headers"`
}

type Scan struct {
	ID             uuid.UUID  `json:"id" db:"id"`
	ProjectID      uuid.UUID  `json:"project_id" db:"project_id"`
	OrgID          uuid.UUID  `json:"org_id" db:"org_id"`
	CreatedBy      uuid.UUID  `json:"created_by" db:"created_by"`
	Name           string     `json:"name" db:"name"`
	Status         ScanStatus `json:"status" db:"status"`
	TargetType     TargetType `json:"target_type" db:"target_type"`
	Config         ScanConfig `json:"config" db:"config"`
	Modules        []string   `json:"modules" db:"modules"`
	ContainerLimit int        `json:"container_limit" db:"container_limit"`
	MaxRetries     int        `json:"max_retries" db:"max_retries"`
	TotalJobs      int        `json:"total_jobs" db:"total_jobs"`
	CompletedJobs  int        `json:"completed_jobs" db:"completed_jobs"`
	FailedJobs     int        `json:"failed_jobs" db:"failed_jobs"`
	CreatedAt      time.Time  `json:"created_at" db:"created_at"`
	StartedAt      *time.Time `json:"started_at" db:"started_at"`
	FinishedAt     *time.Time `json:"finished_at" db:"finished_at"`
	UpdatedAt      time.Time  `json:"updated_at" db:"updated_at"`
}

// ─── Job ──────────────────────────────────────────────────────────────────────

type Job struct {
	ID           uuid.UUID  `json:"id" db:"id"`
	ScanID       uuid.UUID  `json:"scan_id" db:"scan_id"`
	Target       string     `json:"target" db:"target"`
	Module       string     `json:"module" db:"module"`
	Status       JobStatus  `json:"status" db:"status"`
	Attempt      int        `json:"attempt" db:"attempt"`
	MaxAttempts  int        `json:"max_attempts" db:"max_attempts"`
	ErrorMessage string     `json:"error_message" db:"error_message"`
	ContainerID  string     `json:"container_id" db:"container_id"`
	CreatedAt    time.Time  `json:"created_at" db:"created_at"`
	StartedAt    *time.Time `json:"started_at" db:"started_at"`
	FinishedAt   *time.Time `json:"finished_at" db:"finished_at"`

	// Populated when dispatching (not stored in DB)
	ScanConfig ScanConfig `json:"scan_config,omitempty"`
}

// ─── Finding ──────────────────────────────────────────────────────────────────

type Finding struct {
	ID              uuid.UUID  `json:"id" db:"id"`
	ScanID          uuid.UUID  `json:"scan_id" db:"scan_id"`
	JobID           *uuid.UUID `json:"job_id" db:"job_id"`
	Module          string     `json:"module" db:"module"`
	Title           string     `json:"title" db:"title"`
	Description     string     `json:"description" db:"description"`
	Severity        Severity   `json:"severity" db:"severity"`
	CVSSScore       *float64   `json:"cvss_score" db:"cvss_score"`
	CVSSVector      string     `json:"cvss_vector" db:"cvss_vector"`
	Endpoint        string     `json:"endpoint" db:"endpoint"`
	Method          string     `json:"method" db:"method"`
	Request         string     `json:"request" db:"request"`
	Response        string     `json:"response" db:"response"`
	EvidencePath    string     `json:"evidence_path" db:"evidence_path"`
	OWASPRef        string     `json:"owasp_ref" db:"owasp_ref"`
	PCIRequirement  string     `json:"pci_requirement" db:"pci_requirement"`
	CWEID           string     `json:"cwe_id" db:"cwe_id"`
	AISummary       string     `json:"ai_summary" db:"ai_summary"`
	AIRemediation   string     `json:"ai_remediation" db:"ai_remediation"`
	AIPriority      int        `json:"ai_priority" db:"ai_priority"`
	DedupHash       string     `json:"dedup_hash" db:"dedup_hash"`
	IsFalsePositive bool       `json:"is_false_positive" db:"is_false_positive"`
	Status          string     `json:"status" db:"status"`
	RetestedAt      *time.Time `json:"retested_at" db:"retested_at"`
	CreatedAt       time.Time  `json:"created_at" db:"created_at"`
}

// ─── Worker job payload (sent via Redis) ──────────────────────────────────────

type WorkerJob struct {
	ID          uuid.UUID      `json:"id"`
	ScanID      uuid.UUID      `json:"scan_id"`
	Target      string         `json:"target"`
	Module      string         `json:"module"`
	Attempt     int            `json:"attempt"`
	MaxAttempts int            `json:"max_attempts"`
	Auth        AuthConfig     `json:"auth"`
	Config      map[string]any `json:"config"`
}

// ─── Worker result (returned via HTTP) ────────────────────────────────────────

type WorkerResult struct {
	JobID    uuid.UUID        `json:"job_id"`
	ScanID   uuid.UUID        `json:"scan_id"`
	Status   JobStatus        `json:"status"`
	Findings []FindingPayload `json:"findings"`
	Error    string           `json:"error"`
}

type FindingPayload struct {
	Module         string   `json:"module"`
	Title          string   `json:"title"`
	Description    string   `json:"description"`
	Severity       Severity `json:"severity"`
	CVSSScore      *float64 `json:"cvss_score"`
	CVSSVector     string   `json:"cvss_vector"`
	Endpoint       string   `json:"endpoint"`
	Method         string   `json:"method"`
	Request        string   `json:"request"`
	Response       string   `json:"response"`
	OWASPRef       string   `json:"owasp_ref"`
	PCIRequirement string   `json:"pci_requirement"`
	CWEID          string   `json:"cwe_id"`
}

// ─── WebSocket events ─────────────────────────────────────────────────────────

type WSEvent struct {
	Type    string `json:"type"`
	ScanID  string `json:"scan_id"`
	Payload any    `json:"payload"`
}

const (
	WSEventScanStarted   = "scan.started"
	WSEventJobCompleted  = "job.completed"
	WSEventJobFailed     = "job.failed"
	WSEventFindingNew    = "finding.new"
	WSEventScanCompleted = "scan.completed"
	WSEventScanFailed    = "scan.failed"
	WSEventProgress      = "scan.progress"
)

// ─── Failure log entry ────────────────────────────────────────────────────────

type FailureLog struct {
	ID         uuid.UUID  `json:"id" db:"id"`
	ScanID     uuid.UUID  `json:"scan_id" db:"scan_id"`
	JobID      *uuid.UUID `json:"job_id" db:"job_id"`
	Target     string     `json:"target" db:"target"`
	Module     string     `json:"module" db:"module"`
	Attempts   int        `json:"attempts" db:"attempts"`
	FinalError string     `json:"final_error" db:"final_error"`
	CreatedAt  time.Time  `json:"created_at" db:"created_at"`
}

// ─── API request/response types ───────────────────────────────────────────────

type LoginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type LoginResponse struct {
	Token string `json:"token"`
	User  User   `json:"user"`
}

type CreateScanRequest struct {
	ProjectID      string     `json:"project_id"`
	Name           string     `json:"name"`
	TargetType     TargetType `json:"target_type"`
	Config         ScanConfig `json:"config"`
	Modules        []string   `json:"modules"`
	ContainerLimit int        `json:"container_limit"`
	MaxRetries     int        `json:"max_retries"`
}

type ScanProgress struct {
	ScanID        string  `json:"scan_id"`
	Status        string  `json:"status"`
	TotalJobs     int     `json:"total_jobs"`
	CompletedJobs int     `json:"completed_jobs"`
	FailedJobs    int     `json:"failed_jobs"`
	ProgressPct   float64 `json:"progress_pct"`
}
