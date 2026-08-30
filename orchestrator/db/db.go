package db

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"harbore.dev/orchestrator/models"
)

type DB struct {
	pool *pgxpool.Pool
}

func New(ctx context.Context, connStr string) (*DB, error) {
	cfg, err := pgxpool.ParseConfig(connStr)
	if err != nil {
		return nil, fmt.Errorf("parse db config: %w", err)
	}
	cfg.MaxConns = 25
	cfg.MinConns = 5
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create pool: %w", err)
	}

	if err := pool.Ping(ctx); err != nil {
		return nil, fmt.Errorf("ping database: %w", err)
	}

	return &DB{pool: pool}, nil
}

func (d *DB) Close() {
	d.pool.Close()
}

// ─── Users ────────────────────────────────────────────────────────────────────

func (d *DB) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	u := &models.User{}
	err := d.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, name, role, is_active, avatar, created_at, updated_at
		 FROM users WHERE email = $1 AND is_active = true`, email).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Role,
			&u.IsActive, &u.Avatar, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return u, nil
}

func (d *DB) GetUserByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	u := &models.User{}
	err := d.pool.QueryRow(ctx,
		`SELECT id, email, password_hash, name, role, is_active, avatar, created_at, updated_at
		 FROM users WHERE id = $1`, id).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Role,
			&u.IsActive, &u.Avatar, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	return u, nil
}

func (d *DB) CreateUser(ctx context.Context, email, passwordHash, name string, role models.UserRole) (*models.User, error) {
	u := &models.User{}
	err := d.pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, name, role)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, email, password_hash, name, role, is_active, avatar, created_at, updated_at`,
		email, passwordHash, name, role).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Role,
			&u.IsActive, &u.Avatar, &u.CreatedAt, &u.UpdatedAt)
	return u, err
}

// ─── Projects ─────────────────────────────────────────────────────────────────

func (d *DB) CreateProject(ctx context.Context, ownerID uuid.UUID, name, description string) (*models.Project, error) {
	p := &models.Project{}
	err := d.pool.QueryRow(ctx,
		`INSERT INTO projects (owner_id, name, description)
		 VALUES ($1, $2, $3)
		 RETURNING id, owner_id, name, description, created_at, updated_at`,
		ownerID, name, description).
		Scan(&p.ID, &p.OwnerID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt)
	return p, err
}

func (d *DB) ListProjects(ctx context.Context, ownerID uuid.UUID) ([]*models.Project, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT id, owner_id, name, description, created_at, updated_at
		 FROM projects WHERE owner_id = $1 ORDER BY created_at DESC`, ownerID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var projects []*models.Project
	for rows.Next() {
		p := &models.Project{}
		if err := rows.Scan(&p.ID, &p.OwnerID, &p.Name, &p.Description, &p.CreatedAt, &p.UpdatedAt); err != nil {
			return nil, err
		}
		projects = append(projects, p)
	}
	return projects, nil
}

// ─── Scans ────────────────────────────────────────────────────────────────────

func (d *DB) CreateScan(ctx context.Context, req *models.CreateScanRequest, userID, orgID uuid.UUID) (*models.Scan, error) {
	projectID, err := uuid.Parse(req.ProjectID)
	if err != nil {
		return nil, fmt.Errorf("invalid project_id: %w", err)
	}

	// Normalize targets to absolute URLs so scan modules can parse them and
	// issue requests. Without this, schemeless targets silently produce no findings.
	req.Config.Targets = models.NormalizeTargets(req.Config.Targets)

	configJSON, err := json.Marshal(req.Config)
	if err != nil {
		return nil, err
	}

	containerLimit := req.ContainerLimit
	if containerLimit <= 0 {
		containerLimit = 5
	}
	maxRetries := req.MaxRetries
	if maxRetries <= 0 {
		maxRetries = 3
	}

	s := &models.Scan{}
	err = d.pool.QueryRow(ctx,
		`INSERT INTO scans (project_id, org_id, created_by, name, target_type, config, modules, container_limit, max_retries)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		 RETURNING id, project_id, org_id, created_by, name, status, target_type, config::text,
		           modules, container_limit, max_retries, total_jobs, completed_jobs, failed_jobs,
		           created_at, started_at, finished_at, updated_at`,
		projectID, orgID, userID, req.Name, req.TargetType, configJSON,
		req.Modules, containerLimit, maxRetries).
		Scan(&s.ID, &s.ProjectID, &s.OrgID, &s.CreatedBy, &s.Name, &s.Status, &s.TargetType,
			new(string), // scan config as string, we'll unmarshal
			&s.Modules, &s.ContainerLimit, &s.MaxRetries,
			&s.TotalJobs, &s.CompletedJobs, &s.FailedJobs,
			&s.CreatedAt, &s.StartedAt, &s.FinishedAt, &s.UpdatedAt)
	if err != nil {
		return nil, err
	}
	s.Config = req.Config
	return s, nil
}

func (d *DB) GetScan(ctx context.Context, id uuid.UUID) (*models.Scan, error) {
	s := &models.Scan{}
	var configJSON string
	err := d.pool.QueryRow(ctx,
		`SELECT id, project_id, org_id, created_by, name, status, target_type, config::text,
		        modules, container_limit, max_retries, total_jobs, completed_jobs, failed_jobs,
		        created_at, started_at, finished_at, updated_at
		 FROM scans WHERE id = $1`, id).
		Scan(&s.ID, &s.ProjectID, &s.OrgID, &s.CreatedBy, &s.Name, &s.Status, &s.TargetType,
			&configJSON, &s.Modules, &s.ContainerLimit, &s.MaxRetries,
			&s.TotalJobs, &s.CompletedJobs, &s.FailedJobs,
			&s.CreatedAt, &s.StartedAt, &s.FinishedAt, &s.UpdatedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	_ = json.Unmarshal([]byte(configJSON), &s.Config)
	return s, nil
}

func (d *DB) ListScans(ctx context.Context, orgID uuid.UUID) ([]*models.Scan, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT id, project_id, org_id, created_by, name, status, target_type, config::text,
		        modules, container_limit, max_retries, total_jobs, completed_jobs, failed_jobs,
		        created_at, started_at, finished_at, updated_at
		 FROM scans WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var scans []*models.Scan
	for rows.Next() {
		s := &models.Scan{}
		var configJSON string
		if err := rows.Scan(&s.ID, &s.ProjectID, &s.OrgID, &s.CreatedBy, &s.Name, &s.Status,
			&s.TargetType, &configJSON, &s.Modules, &s.ContainerLimit, &s.MaxRetries,
			&s.TotalJobs, &s.CompletedJobs, &s.FailedJobs,
			&s.CreatedAt, &s.StartedAt, &s.FinishedAt, &s.UpdatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(configJSON), &s.Config)
		scans = append(scans, s)
	}
	return scans, nil
}

func (d *DB) UpdateScanStatus(ctx context.Context, id uuid.UUID, status models.ScanStatus) error {
	var q string
	switch status {
	case models.ScanRunning:
		q = `UPDATE scans SET status = $2, started_at = NOW() WHERE id = $1`
	case models.ScanCompleted, models.ScanFailed, models.ScanCancelled:
		q = `UPDATE scans SET status = $2, finished_at = NOW() WHERE id = $1`
	default:
		q = `UPDATE scans SET status = $2 WHERE id = $1`
	}
	_, err := d.pool.Exec(ctx, q, id, status)
	return err
}

func (d *DB) UpdateScanProgress(ctx context.Context, id uuid.UUID, totalJobs, completedJobs, failedJobs int) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE scans SET total_jobs = $2, completed_jobs = $3, failed_jobs = $4 WHERE id = $1`,
		id, totalJobs, completedJobs, failedJobs)
	return err
}

// ─── Jobs ─────────────────────────────────────────────────────────────────────

func (d *DB) CreateJob(ctx context.Context, scanID uuid.UUID, target, module string, maxAttempts int) (*models.Job, error) {
	j := &models.Job{}
	var errMsg, containerID *string // nullable columns
	err := d.pool.QueryRow(ctx,
		`INSERT INTO jobs (scan_id, target, module, max_attempts)
		 VALUES ($1, $2, $3, $4)
		 RETURNING id, scan_id, target, module, status, attempt, max_attempts,
		           error_message, container_id, created_at, started_at, finished_at`,
		scanID, target, module, maxAttempts).
		Scan(&j.ID, &j.ScanID, &j.Target, &j.Module, &j.Status, &j.Attempt,
			&j.MaxAttempts, &errMsg, &containerID,
			&j.CreatedAt, &j.StartedAt, &j.FinishedAt)
	if err != nil {
		return nil, err
	}
	if errMsg != nil {
		j.ErrorMessage = *errMsg
	}
	if containerID != nil {
		j.ContainerID = *containerID
	}
	return j, nil
}

func (d *DB) UpdateJobStatus(ctx context.Context, id uuid.UUID, status models.JobStatus, errMsg string) error {
	var q string
	switch status {
	case models.JobRunning:
		q = `UPDATE jobs SET status = $2, started_at = NOW() WHERE id = $1`
	case models.JobCompleted, models.JobFailed:
		q = `UPDATE jobs SET status = $2, error_message = $3, finished_at = NOW() WHERE id = $1`
	default:
		q = `UPDATE jobs SET status = $2, error_message = $3 WHERE id = $1`
	}
	if status == models.JobCompleted || status == models.JobFailed {
		_, err := d.pool.Exec(ctx, q, id, status, errMsg)
		return err
	}
	_, err := d.pool.Exec(ctx, q, id, status)
	return err
}

func (d *DB) GetJob(ctx context.Context, id uuid.UUID) (*models.Job, error) {
	j := &models.Job{}
	var errMsg, containerID *string // nullable columns
	err := d.pool.QueryRow(ctx,
		`SELECT id, scan_id, target, module, status, attempt, max_attempts,
		        error_message, container_id, created_at, started_at, finished_at
		 FROM jobs WHERE id = $1`, id).
		Scan(&j.ID, &j.ScanID, &j.Target, &j.Module, &j.Status, &j.Attempt,
			&j.MaxAttempts, &errMsg, &containerID,
			&j.CreatedAt, &j.StartedAt, &j.FinishedAt)
	if err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	if errMsg != nil {
		j.ErrorMessage = *errMsg
	}
	if containerID != nil {
		j.ContainerID = *containerID
	}
	return j, nil
}

func (d *DB) IncrementJobAttempt(ctx context.Context, id uuid.UUID) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE jobs SET attempt = attempt + 1, status = 'retrying' WHERE id = $1`, id)
	return err
}

// ─── Findings ─────────────────────────────────────────────────────────────────

func (d *DB) CreateFinding(ctx context.Context, scanID uuid.UUID, jobID *uuid.UUID, f *models.FindingPayload) error {
	hash := sha256.Sum256([]byte(f.Module + "|" + f.Endpoint + "|" + f.Title))
	dedupHash := fmt.Sprintf("%x", hash)

	// Check for duplicate
	var exists bool
	_ = d.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM findings WHERE scan_id = $1 AND dedup_hash = $2)`,
		scanID, dedupHash).Scan(&exists)
	if exists {
		return nil
	}

	_, err := d.pool.Exec(ctx,
		`INSERT INTO findings (scan_id, job_id, module, title, description, severity,
		  cvss_score, cvss_vector, endpoint, method, request, response,
		  owasp_ref, pci_requirement, cwe_id, dedup_hash)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)`,
		scanID, jobID, f.Module, f.Title, f.Description, f.Severity,
		f.CVSSScore, f.CVSSVector, f.Endpoint, f.Method, f.Request, f.Response,
		f.OWASPRef, f.PCIRequirement, f.CWEID, dedupHash)
	return err
}

func (d *DB) ListFindings(ctx context.Context, scanID uuid.UUID) ([]*models.Finding, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT id, scan_id, job_id, module, title, description, severity,
		        cvss_score, cvss_vector, endpoint, method, request, response, evidence_path,
		        owasp_ref, pci_requirement, cwe_id, ai_summary, ai_remediation, ai_priority,
		        dedup_hash, is_false_positive, status, retested_at, created_at
		 FROM findings WHERE scan_id = $1 ORDER BY severity, created_at DESC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var findings []*models.Finding
	for rows.Next() {
		f := &models.Finding{}
		// Nullable columns not always populated (AI off, no evidence): scan via pointers.
		var evidencePath, aiSummary, aiRemediation *string
		var aiPriority *int
		var cvssVector, endpoint, method, request, response, owaspRef, pciReq, cweID *string
		if err := rows.Scan(&f.ID, &f.ScanID, &f.JobID, &f.Module, &f.Title,
			&f.Description, &f.Severity, &f.CVSSScore, &cvssVector, &endpoint,
			&method, &request, &response, &evidencePath,
			&owaspRef, &pciReq, &cweID, &aiSummary,
			&aiRemediation, &aiPriority, &f.DedupHash, &f.IsFalsePositive, &f.Status, &f.RetestedAt, &f.CreatedAt); err != nil {
			return nil, err
		}
		if cvssVector != nil {
			f.CVSSVector = *cvssVector
		}
		if endpoint != nil {
			f.Endpoint = *endpoint
		}
		if method != nil {
			f.Method = *method
		}
		if request != nil {
			f.Request = *request
		}
		if response != nil {
			f.Response = *response
		}
		if evidencePath != nil {
			f.EvidencePath = *evidencePath
		}
		if owaspRef != nil {
			f.OWASPRef = *owaspRef
		}
		if pciReq != nil {
			f.PCIRequirement = *pciReq
		}
		if cweID != nil {
			f.CWEID = *cweID
		}
		if aiSummary != nil {
			f.AISummary = *aiSummary
		}
		if aiRemediation != nil {
			f.AIRemediation = *aiRemediation
		}
		if aiPriority != nil {
			f.AIPriority = *aiPriority
		}
		findings = append(findings, f)
	}
	return findings, nil
}

// ─── Failure log ──────────────────────────────────────────────────────────────

func (d *DB) CreateFailureLog(ctx context.Context, scanID uuid.UUID, jobID *uuid.UUID, target, module string, attempts int, finalErr string) error {
	_, err := d.pool.Exec(ctx,
		`INSERT INTO failure_log (scan_id, job_id, target, module, attempts, final_error)
		 VALUES ($1, $2, $3, $4, $5, $6)`,
		scanID, jobID, target, module, attempts, finalErr)
	return err
}

func (d *DB) ListFailures(ctx context.Context, scanID uuid.UUID) ([]*models.FailureLog, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT id, scan_id, job_id, target, module, attempts, final_error, created_at
		 FROM failure_log WHERE scan_id = $1 ORDER BY created_at DESC`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var failures []*models.FailureLog
	for rows.Next() {
		fl := &models.FailureLog{}
		if err := rows.Scan(&fl.ID, &fl.ScanID, &fl.JobID, &fl.Target,
			&fl.Module, &fl.Attempts, &fl.FinalError, &fl.CreatedAt); err != nil {
			return nil, err
		}
		failures = append(failures, fl)
	}
	return failures, nil
}

// ─── Stats ────────────────────────────────────────────────────────────────────

func (d *DB) GetScanFindingStats(ctx context.Context, scanID uuid.UUID) (map[string]int, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT severity, COUNT(*) FROM findings
		 WHERE scan_id = $1 AND is_false_positive = false
		 GROUP BY severity`, scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := map[string]int{}
	for rows.Next() {
		var sev string
		var count int
		if err := rows.Scan(&sev, &count); err != nil {
			return nil, err
		}
		stats[sev] = count
	}
	return stats, nil
}

// ─── Debug console (TEMPORARY) ─────────────────────────────────────────────────
// These helpers back the debug console (GET /api/v1/debug/*). They read the jobs
// table across all scans so operators can see successful and failed jobs while
// diagnosing module execution. Remove alongside the console when no longer needed.

// ListRecentJobs returns jobs across all scans, most recent first, with optional
// status and scan_id filters. error_message and container_id are nullable in the
// schema, so they are scanned via *string to avoid NULL-scan errors.
func (d *DB) ListRecentJobs(ctx context.Context, statusFilter, scanID string, limit int) ([]*models.Job, error) {
	if limit <= 0 || limit > 1000 {
		limit = 200
	}

	q := `SELECT id, scan_id, target, module, status, attempt, max_attempts,
	             error_message, container_id, created_at, started_at, finished_at
	      FROM jobs`

	conds := []string{}
	args := []any{}
	i := 1
	if statusFilter != "" && statusFilter != "all" {
		conds = append(conds, fmt.Sprintf("status = $%d", i))
		args = append(args, statusFilter)
		i++
	}
	if scanID != "" {
		conds = append(conds, fmt.Sprintf("scan_id = $%d", i))
		args = append(args, scanID)
		i++
	}
	if len(conds) > 0 {
		q += " WHERE " + strings.Join(conds, " AND ")
	}
	q += fmt.Sprintf(" ORDER BY created_at DESC LIMIT $%d", i)
	args = append(args, limit)

	rows, err := d.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var jobs []*models.Job
	for rows.Next() {
		j := &models.Job{}
		var errMsg, containerID *string
		if err := rows.Scan(&j.ID, &j.ScanID, &j.Target, &j.Module, &j.Status,
			&j.Attempt, &j.MaxAttempts, &errMsg, &containerID,
			&j.CreatedAt, &j.StartedAt, &j.FinishedAt); err != nil {
			return nil, err
		}
		if errMsg != nil {
			j.ErrorMessage = *errMsg
		}
		if containerID != nil {
			j.ContainerID = *containerID
		}
		jobs = append(jobs, j)
	}
	return jobs, rows.Err()
}

// CountJobsByStatus returns a map of job status -> count across all scans.
func (d *DB) CountJobsByStatus(ctx context.Context) (map[string]int, error) {
	rows, err := d.pool.Query(ctx, `SELECT status, COUNT(*) FROM jobs GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	counts := map[string]int{}
	for rows.Next() {
		var status string
		var n int
		if err := rows.Scan(&status, &n); err != nil {
			return nil, err
		}
		counts[status] = n
	}
	return counts, rows.Err()
}

// ─── Settings (profile / password) ────────────────────────────────────────────

func (d *DB) UpdateUserProfile(ctx context.Context, id uuid.UUID, name, avatar string) (*models.User, error) {
	u := &models.User{}
	err := d.pool.QueryRow(ctx,
		`UPDATE users SET name = $2, avatar = $3, updated_at = NOW() WHERE id = $1
		 RETURNING id, email, password_hash, name, role, is_active, avatar, created_at, updated_at`,
		id, name, avatar).
		Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Name, &u.Role, &u.IsActive, &u.Avatar, &u.CreatedAt, &u.UpdatedAt)
	if err != nil {
		return nil, err
	}
	return u, nil
}

func (d *DB) UpdateUserPassword(ctx context.Context, id uuid.UUID, passwordHash string) error {
	_, err := d.pool.Exec(ctx, `UPDATE users SET password_hash = $2, updated_at = NOW() WHERE id = $1`, id, passwordHash)
	return err
}

// ─── Organizations (multi-tenancy) ────────────────────────────────────────────

func (d *DB) ListOrgsForUser(ctx context.Context, userID uuid.UUID) ([]*models.Organization, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT o.id, o.name, m.role, o.created_at
		 FROM organizations o JOIN organization_members m ON m.org_id = o.id
		 WHERE m.user_id = $1 ORDER BY o.name`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var orgs []*models.Organization
	for rows.Next() {
		o := &models.Organization{}
		if err := rows.Scan(&o.ID, &o.Name, &o.Role, &o.CreatedAt); err != nil {
			return nil, err
		}
		orgs = append(orgs, o)
	}
	return orgs, rows.Err()
}

func (d *DB) IsOrgMember(ctx context.Context, userID, orgID uuid.UUID) (bool, error) {
	var exists bool
	err := d.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM organization_members WHERE user_id = $1 AND org_id = $2)`,
		userID, orgID).Scan(&exists)
	return exists, err
}

func (d *DB) CreateOrg(ctx context.Context, name string, creatorID uuid.UUID) (*models.Organization, error) {
	o := &models.Organization{}
	if err := d.pool.QueryRow(ctx,
		`INSERT INTO organizations (name) VALUES ($1) RETURNING id, name, created_at`,
		name).Scan(&o.ID, &o.Name, &o.CreatedAt); err != nil {
		return nil, err
	}
	if _, err := d.pool.Exec(ctx,
		`INSERT INTO organization_members (org_id, user_id, role) VALUES ($1, $2, 'admin')`,
		o.ID, creatorID); err != nil {
		return nil, err
	}
	o.Role = "admin"
	return o, nil
}

func (d *DB) AddOrgMemberByEmail(ctx context.Context, orgID uuid.UUID, email, role string) error {
	var uid uuid.UUID
	if err := d.pool.QueryRow(ctx, `SELECT id FROM users WHERE email = $1`, email).Scan(&uid); err != nil {
		if err == pgx.ErrNoRows {
			return fmt.Errorf("no user with email %s", email)
		}
		return err
	}
	if role == "" {
		role = "member"
	}
	_, err := d.pool.Exec(ctx,
		`INSERT INTO organization_members (org_id, user_id, role) VALUES ($1, $2, $3)
		 ON CONFLICT (org_id, user_id) DO UPDATE SET role = EXCLUDED.role`,
		orgID, uid, role)
	return err
}

// ─── TLS certificates ─────────────────────────────────────────────────────────

func (d *DB) UpsertCertificate(ctx context.Context, c *models.Certificate) (*models.Certificate, error) {
	out := &models.Certificate{}
	err := d.pool.QueryRow(ctx,
		`INSERT INTO certificates
		   (org_id, host, port, common_name, issuer, sans, not_before, not_after,
		    key_type, key_bits, sig_alg, tls_version, error, last_checked_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,NOW())
		 ON CONFLICT (org_id, host, port) DO UPDATE SET
		    common_name=EXCLUDED.common_name, issuer=EXCLUDED.issuer, sans=EXCLUDED.sans,
		    not_before=EXCLUDED.not_before, not_after=EXCLUDED.not_after,
		    key_type=EXCLUDED.key_type, key_bits=EXCLUDED.key_bits, sig_alg=EXCLUDED.sig_alg,
		    tls_version=EXCLUDED.tls_version, error=EXCLUDED.error, last_checked_at=NOW()
		 RETURNING id, org_id, host, port, common_name, issuer, sans, not_before, not_after,
		           key_type, key_bits, sig_alg, tls_version, error, last_checked_at, created_at`,
		c.OrgID, c.Host, c.Port, c.CommonName, c.Issuer, c.SANs, c.NotBefore, c.NotAfter,
		c.KeyType, c.KeyBits, c.SigAlg, c.TLSVersion, c.Error).
		Scan(&out.ID, &out.OrgID, &out.Host, &out.Port, &out.CommonName, &out.Issuer, &out.SANs,
			&out.NotBefore, &out.NotAfter, &out.KeyType, &out.KeyBits, &out.SigAlg,
			&out.TLSVersion, &out.Error, &out.LastCheckedAt, &out.CreatedAt)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (d *DB) ListCertificates(ctx context.Context, orgID uuid.UUID) ([]*models.Certificate, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT id, org_id, host, port, common_name, issuer, sans, not_before, not_after,
		        key_type, key_bits, sig_alg, tls_version, error, last_checked_at, created_at
		 FROM certificates WHERE org_id=$1 ORDER BY not_after ASC NULLS FIRST`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Certificate
	for rows.Next() {
		c := &models.Certificate{}
		if err := rows.Scan(&c.ID, &c.OrgID, &c.Host, &c.Port, &c.CommonName, &c.Issuer, &c.SANs,
			&c.NotBefore, &c.NotAfter, &c.KeyType, &c.KeyBits, &c.SigAlg, &c.TLSVersion,
			&c.Error, &c.LastCheckedAt, &c.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (d *DB) DeleteCertificate(ctx context.Context, id, orgID uuid.UUID) error {
	_, err := d.pool.Exec(ctx, `DELETE FROM certificates WHERE id=$1 AND org_id=$2`, id, orgID)
	return err
}

// ─── Assets (CMDB) ────────────────────────────────────────────────────────────

// UpsertAsset inserts or updates discovery data for an asset, preserving any
// existing CMDB edits (label/owner/criticality/classification) on re-import.
func (d *DB) UpsertAsset(ctx context.Context, a *models.Asset) error {
	ports := a.Ports
	if len(ports) == 0 {
		ports = []byte("[]")
	}
	_, err := d.pool.Exec(ctx,
		`INSERT INTO assets (org_id, ip, hostname, mac, vendor, subnet, ports, is_scanner, source, discovered_at, updated_at)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW(),NOW())
		 ON CONFLICT (org_id, ip) DO UPDATE SET
		   hostname=EXCLUDED.hostname, mac=EXCLUDED.mac, vendor=EXCLUDED.vendor,
		   subnet=EXCLUDED.subnet, ports=EXCLUDED.ports, is_scanner=EXCLUDED.is_scanner,
		   source=EXCLUDED.source, updated_at=NOW()`,
		a.OrgID, a.IP, a.Hostname, a.MAC, a.Vendor, a.Subnet, ports, a.IsScanner, a.Source)
	return err
}

func (d *DB) ListAssets(ctx context.Context, orgID uuid.UUID) ([]*models.Asset, error) {
	rows, err := d.pool.Query(ctx,
		`SELECT id, org_id, ip, hostname, mac, vendor, subnet, ports, is_scanner,
		        label, owner, criticality, classification, source, discovered_at, updated_at
		 FROM assets WHERE org_id=$1 ORDER BY ip`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*models.Asset
	for rows.Next() {
		a := &models.Asset{}
		if err := rows.Scan(&a.ID, &a.OrgID, &a.IP, &a.Hostname, &a.MAC, &a.Vendor, &a.Subnet,
			&a.Ports, &a.IsScanner, &a.Label, &a.Owner, &a.Criticality, &a.Classification,
			&a.Source, &a.DiscoveredAt, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (d *DB) UpdateAssetCMDB(ctx context.Context, id, orgID uuid.UUID, label, owner, criticality, classification string) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE assets SET label=$3, owner=$4, criticality=$5, classification=$6, updated_at=NOW()
		 WHERE id=$1 AND org_id=$2`, id, orgID, label, owner, criticality, classification)
	return err
}

func (d *DB) ClearAssets(ctx context.Context, orgID uuid.UUID) error {
	_, err := d.pool.Exec(ctx, `DELETE FROM assets WHERE org_id=$1`, orgID)
	return err
}

// SetFindingStatus updates a finding's remediation status (open|fixed) after a retest.
func (d *DB) SetFindingStatus(ctx context.Context, id uuid.UUID, status string, retestedAt *time.Time) error {
	_, err := d.pool.Exec(ctx,
		`UPDATE findings SET status=$2, retested_at=$3 WHERE id=$1`, id, status, retestedAt)
	return err
}
