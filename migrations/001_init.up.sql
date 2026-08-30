-- Harbore Database Schema
-- Migration: 001_init

CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pg_trgm";

-- ─── Enums ────────────────────────────────────────────────────────────────────

CREATE TYPE user_role AS ENUM ('admin', 'analyst', 'viewer');
CREATE TYPE scan_status AS ENUM ('pending', 'running', 'completed', 'failed', 'cancelled');
CREATE TYPE job_status AS ENUM ('queued', 'running', 'completed', 'failed', 'retrying');
CREATE TYPE finding_severity AS ENUM ('critical', 'high', 'medium', 'low', 'info');
CREATE TYPE target_type AS ENUM ('openapi', 'postman', 'graphql', 'soap', 'url_list', 'har', 'mcp', 'single_url');

-- ─── Users ────────────────────────────────────────────────────────────────────

CREATE TABLE users (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    email         TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    name          TEXT NOT NULL,
    role          user_role NOT NULL DEFAULT 'analyst',
    is_active     BOOLEAN NOT NULL DEFAULT true,
    avatar        TEXT NOT NULL DEFAULT '',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- ─── Organizations (multi-tenancy) ────────────────────────────────────────────
CREATE TABLE organizations (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE organization_members (
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX idx_org_members_user ON organization_members(user_id);

-- ─── TLS certificate monitoring ───────────────────────────────────────────────
CREATE TABLE certificates (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id          UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    host            TEXT NOT NULL,
    port            INT  NOT NULL DEFAULT 443,
    common_name     TEXT NOT NULL DEFAULT '',
    issuer          TEXT NOT NULL DEFAULT '',
    sans            TEXT[] NOT NULL DEFAULT '{}',
    not_before      TIMESTAMPTZ,
    not_after       TIMESTAMPTZ,
    key_type        TEXT NOT NULL DEFAULT '',
    key_bits        INT  NOT NULL DEFAULT 0,
    sig_alg         TEXT NOT NULL DEFAULT '',
    tls_version     TEXT NOT NULL DEFAULT '',
    error           TEXT NOT NULL DEFAULT '',
    last_checked_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, host, port)
);
CREATE INDEX idx_certificates_org ON certificates(org_id);

-- ─── Discovered assets (CMDB) ─────────────────────────────────────────────────
CREATE TABLE assets (
    id             UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    org_id         UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    ip             TEXT NOT NULL,
    hostname       TEXT NOT NULL DEFAULT '',
    mac            TEXT NOT NULL DEFAULT '',
    vendor         TEXT NOT NULL DEFAULT '',
    subnet         TEXT NOT NULL DEFAULT '',
    ports          JSONB NOT NULL DEFAULT '[]',
    is_scanner     BOOLEAN NOT NULL DEFAULT false,
    label          TEXT NOT NULL DEFAULT '',
    owner          TEXT NOT NULL DEFAULT '',
    criticality    TEXT NOT NULL DEFAULT '',
    classification TEXT NOT NULL DEFAULT '',
    source         TEXT NOT NULL DEFAULT 'agent',
    discovered_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (org_id, ip)
);
CREATE INDEX idx_assets_org ON assets(org_id);

CREATE INDEX idx_users_email ON users(email);

-- ─── Projects ─────────────────────────────────────────────────────────────────

CREATE TABLE projects (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    owner_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_projects_owner ON projects(owner_id);

-- ─── Scans ────────────────────────────────────────────────────────────────────

CREATE TABLE scans (
    id                  UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    project_id          UUID NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    org_id              UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    created_by          UUID NOT NULL REFERENCES users(id),
    name                TEXT NOT NULL,
    status              scan_status NOT NULL DEFAULT 'pending',
    target_type         target_type NOT NULL,

    -- Scan configuration stored as JSONB for flexibility
    config              JSONB NOT NULL DEFAULT '{}',

    -- Module selection: array of module names to run
    modules             TEXT[] NOT NULL DEFAULT '{}',

    -- Container limit set by user
    container_limit     INT NOT NULL DEFAULT 5,
    max_retries         INT NOT NULL DEFAULT 3,

    -- Progress tracking
    total_jobs          INT NOT NULL DEFAULT 0,
    completed_jobs      INT NOT NULL DEFAULT 0,
    failed_jobs         INT NOT NULL DEFAULT 0,

    -- Timestamps
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at          TIMESTAMPTZ,
    finished_at         TIMESTAMPTZ,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_scans_project ON scans(project_id);
CREATE INDEX idx_scans_status  ON scans(status);
CREATE INDEX idx_scans_created ON scans(created_at DESC);

-- ─── Jobs ─────────────────────────────────────────────────────────────────────

CREATE TABLE jobs (
    id              UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id         UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    target          TEXT NOT NULL,        -- The URL / endpoint being tested
    module          TEXT NOT NULL,        -- Which module runs this job
    status          job_status NOT NULL DEFAULT 'queued',
    attempt         INT NOT NULL DEFAULT 1,
    max_attempts    INT NOT NULL DEFAULT 3,
    error_message   TEXT,
    container_id    TEXT,                 -- Docker container ID running this job
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    started_at      TIMESTAMPTZ,
    finished_at     TIMESTAMPTZ
);

CREATE INDEX idx_jobs_scan    ON jobs(scan_id);
CREATE INDEX idx_jobs_status  ON jobs(status);
CREATE INDEX idx_jobs_module  ON jobs(module);

-- ─── Findings ─────────────────────────────────────────────────────────────────

CREATE TABLE findings (
    id               UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id          UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    job_id           UUID REFERENCES jobs(id) ON DELETE SET NULL,
    module           TEXT NOT NULL,
    title            TEXT NOT NULL,
    description      TEXT NOT NULL,
    severity         finding_severity NOT NULL,
    cvss_score       NUMERIC(4,1),
    cvss_vector      TEXT,

    -- Target info
    endpoint         TEXT,
    method           TEXT,

    -- Evidence
    request          TEXT,
    response         TEXT,
    evidence_path    TEXT,              -- Path in object store

    -- Framework mappings
    owasp_ref        TEXT,             -- e.g. "A03:2021 - Injection"
    pci_requirement  TEXT,             -- e.g. "Req 6.2.4"
    cwe_id           TEXT,             -- e.g. "CWE-89"

    -- AI enrichment
    ai_summary       TEXT,
    ai_remediation   TEXT,
    ai_priority      INT,              -- AI-assigned priority 1-10

    -- Dedup hash (SHA256 of title+endpoint+module)
    dedup_hash       TEXT NOT NULL,

    is_false_positive BOOLEAN NOT NULL DEFAULT false,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_findings_scan      ON findings(scan_id);
CREATE INDEX idx_findings_severity  ON findings(severity);
CREATE INDEX idx_findings_module    ON findings(module);
CREATE INDEX idx_findings_dedup     ON findings(scan_id, dedup_hash);

-- ─── Failure log ──────────────────────────────────────────────────────────────

CREATE TABLE failure_log (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id       UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    job_id        UUID REFERENCES jobs(id) ON DELETE SET NULL,
    target        TEXT NOT NULL,
    module        TEXT NOT NULL,
    attempts      INT NOT NULL DEFAULT 1,
    final_error   TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_failure_log_scan ON failure_log(scan_id);

-- ─── Reports ──────────────────────────────────────────────────────────────────

CREATE TABLE reports (
    id            UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    scan_id       UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    format        TEXT NOT NULL,       -- 'docx' | 'pdf'
    file_path     TEXT NOT NULL,
    generated_by  UUID REFERENCES users(id),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_reports_scan ON reports(scan_id);

-- ─── API keys (for CLI / external integrations) ────────────────────────────────

CREATE TABLE api_keys (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT NOT NULL,
    key_hash    TEXT NOT NULL UNIQUE,
    last_used   TIMESTAMPTZ,
    expires_at  TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_api_keys_user ON api_keys(user_id);
CREATE INDEX idx_api_keys_hash ON api_keys(key_hash);

-- ─── Audit log ────────────────────────────────────────────────────────────────

CREATE TABLE audit_log (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id     UUID REFERENCES users(id) ON DELETE SET NULL,
    action      TEXT NOT NULL,
    resource    TEXT NOT NULL,
    resource_id UUID,
    ip_address  TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_audit_user     ON audit_log(user_id);
CREATE INDEX idx_audit_resource ON audit_log(resource, resource_id);
CREATE INDEX idx_audit_created  ON audit_log(created_at DESC);

-- ─── Updated_at trigger ───────────────────────────────────────────────────────

CREATE OR REPLACE FUNCTION update_updated_at()
RETURNS TRIGGER AS $$
BEGIN NEW.updated_at = NOW(); RETURN NEW; END;
$$ LANGUAGE plpgsql;

CREATE TRIGGER trg_users_updated    BEFORE UPDATE ON users    FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_projects_updated BEFORE UPDATE ON projects FOR EACH ROW EXECUTE FUNCTION update_updated_at();
CREATE TRIGGER trg_scans_updated    BEFORE UPDATE ON scans    FOR EACH ROW EXECUTE FUNCTION update_updated_at();

-- ─── Seed: default admin user ─────────────────────────────────────────────────
-- Password: password (bcrypt, cost 12) — CHANGE IMMEDIATELY in production

INSERT INTO users (email, password_hash, name, role) VALUES
('admin@harbore.local', '$2b$12$u5ka6Auy.F4mDRkHqqLW4.K.aSKfYZyKEzE87iw46oUaH3SewTM8C', 'Harbore Admin', 'admin')
ON CONFLICT (email) DO NOTHING;

-- ─── Seed: default project ────────────────────────────────────────────────────
-- The frontend uses this fixed UUID as the default project. It is owned by the
-- seeded admin user. Without this row, scan creation fails with a foreign-key
-- violation on scans.project_id.

INSERT INTO projects (id, owner_id, name, description)
SELECT '00000000-0000-0000-0000-000000000000', id, 'Default Project', 'Auto-created default project'
FROM users WHERE email = 'admin@harbore.local'
ON CONFLICT (id) DO NOTHING;

-- ─── Seed: default organization + admin membership ───────────────────────────
INSERT INTO organizations (id, name)
VALUES ('00000000-0000-0000-0000-0000000000a1', 'CB-Advisory')
ON CONFLICT (id) DO NOTHING;

INSERT INTO organization_members (org_id, user_id, role)
SELECT '00000000-0000-0000-0000-0000000000a1', id, 'admin' FROM users WHERE email = 'admin@harbore.local'
ON CONFLICT (org_id, user_id) DO NOTHING;

-- ─── Finding remediation status (for retest) ──────────────────────────────────
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS retested_at TIMESTAMPTZ;
