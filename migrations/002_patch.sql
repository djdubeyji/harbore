-- ─────────────────────────────────────────────────────────────────────────────
-- Idempotent schema patch. Safe to run on EVERY startup and on any existing
-- database. Because Postgres only runs /docker-entrypoint-initdb.d scripts once
-- (when the data volume is first created), additive schema changes must live
-- here and be re-applied by `make up` so existing databases stay up to date.
-- Every statement is guarded (IF NOT EXISTS / ON CONFLICT) — no data loss.
-- ─────────────────────────────────────────────────────────────────────────────

-- Users: avatar (Settings)
ALTER TABLE users ADD COLUMN IF NOT EXISTS avatar TEXT NOT NULL DEFAULT '';

-- Multi-org tenancy
CREATE TABLE IF NOT EXISTS organizations (
    id          UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name        TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS organization_members (
    org_id     UUID NOT NULL REFERENCES organizations(id) ON DELETE CASCADE,
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role       TEXT NOT NULL DEFAULT 'member',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (org_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_org_members_user ON organization_members(user_id);

-- Default organization + admin membership
INSERT INTO organizations (id, name)
VALUES ('00000000-0000-0000-0000-0000000000a1', 'CB-Advisory')
ON CONFLICT (id) DO NOTHING;

INSERT INTO organization_members (org_id, user_id, role)
SELECT '00000000-0000-0000-0000-0000000000a1', id, 'admin' FROM users WHERE email = 'admin@harbore.local'
ON CONFLICT (org_id, user_id) DO NOTHING;

-- Scans: org scoping (added nullable for existing rows, then backfilled)
ALTER TABLE scans ADD COLUMN IF NOT EXISTS org_id UUID REFERENCES organizations(id);
UPDATE scans SET org_id = '00000000-0000-0000-0000-0000000000a1' WHERE org_id IS NULL;

-- TLS certificate monitoring
CREATE TABLE IF NOT EXISTS certificates (
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
CREATE INDEX IF NOT EXISTS idx_certificates_org ON certificates(org_id);

-- Discovered assets (CMDB)
CREATE TABLE IF NOT EXISTS assets (
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
CREATE INDEX IF NOT EXISTS idx_assets_org ON assets(org_id);

-- Finding remediation status (retest)
ALTER TABLE findings ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'open';
ALTER TABLE findings ADD COLUMN IF NOT EXISTS retested_at TIMESTAMPTZ;
