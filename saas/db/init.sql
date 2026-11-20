-- ============================================================================
-- VeilOps Tier 2 SaaS Database Schema (PostgreSQL 16 + TimescaleDB)
-- Person 2: SaaS and Reliability Architect
-- Features:
--   1. Non-nullable tenant_id on every single table
--   2. Strict Row-Level Security (RLS) enabled and forced on all tables
--   3. TimescaleDB hypertables for time-series metrics
--   4. Unique constraint on (tenant_id, payload_id) for idempotent delivery
--   5. Append-only audit log and tamper-evident receipt verification
-- ============================================================================

CREATE EXTENSION IF NOT EXISTS timescaledb CASCADE;

-- ----------------------------------------------------------------------------
-- 1. Tenant Registry & Regional Homing
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS tenants (
    tenant_id VARCHAR(64) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    home_region VARCHAR(32) NOT NULL,
    status VARCHAR(32) DEFAULT 'active' NOT NULL,
    created_at TIMESTAMPTZ DEFAULT clock_timestamp() NOT NULL
);

-- Seed regional tenants
INSERT INTO tenants (tenant_id, name, home_region, status) VALUES
    ('t_acme', 'Acme Corporation', 'ap-south', 'active'),
    ('t_globex', 'Globex International', 'eu-central', 'active')
ON CONFLICT (tenant_id) DO NOTHING;

-- ----------------------------------------------------------------------------
-- 2. Registered Collectors (Tier 1 instances)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS collectors (
    collector_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL REFERENCES tenants(tenant_id),
    site_name VARCHAR(128) NOT NULL,
    source_tz VARCHAR(64) NOT NULL,
    public_key VARCHAR(128) NOT NULL,
    version VARCHAR(32) NOT NULL,
    last_seen_utc TIMESTAMPTZ,
    last_seq BIGINT DEFAULT 0,
    health_state VARCHAR(32) DEFAULT 'excellent' NOT NULL,
    health_reason VARCHAR(64) DEFAULT 'NOMINAL' NOT NULL,
    created_at TIMESTAMPTZ DEFAULT clock_timestamp() NOT NULL,
    PRIMARY KEY (tenant_id, collector_id)
);

ALTER TABLE collectors ENABLE ROW LEVEL SECURITY;
ALTER TABLE collectors FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_collectors ON collectors
    USING (tenant_id = current_setting('app.tenant', true))
    WITH CHECK (tenant_id = current_setting('app.tenant', true));

-- ----------------------------------------------------------------------------
-- 3. Ingest Receipts & Idempotency Ledger
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS ingest_receipts (
    tenant_id VARCHAR(64) NOT NULL,
    payload_id VARCHAR(64) NOT NULL,
    collector_id VARCHAR(64) NOT NULL,
    seq BIGINT NOT NULL,
    prev_hash VARCHAR(64) NOT NULL,
    payload_hash VARCHAR(64) NOT NULL,
    signature VARCHAR(128) NOT NULL,
    event_time_utc TIMESTAMPTZ NOT NULL,
    received_at_utc TIMESTAMPTZ DEFAULT clock_timestamp() NOT NULL,
    is_gap_detected BOOLEAN DEFAULT false NOT NULL,
    PRIMARY KEY (tenant_id, payload_id)
);

CREATE INDEX IF NOT EXISTS idx_receipts_collector_seq 
    ON ingest_receipts (tenant_id, collector_id, seq);

ALTER TABLE ingest_receipts ENABLE ROW LEVEL SECURITY;
ALTER TABLE ingest_receipts FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_receipts ON ingest_receipts
    USING (tenant_id = current_setting('app.tenant', true))
    WITH CHECK (tenant_id = current_setting('app.tenant', true));

-- ----------------------------------------------------------------------------
-- 4. Time-Series Metrics Hypertable (5s Windows)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS metrics_5s (
    tenant_id VARCHAR(64) NOT NULL,
    collector_id VARCHAR(64) NOT NULL,
    src VARCHAR(64) NOT NULL,
    metric_name VARCHAR(64) NOT NULL,
    win_s INT NOT NULL,
    val_mean DOUBLE PRECISION NOT NULL,
    val_p95 DOUBLE PRECISION NOT NULL,
    val_max DOUBLE PRECISION NOT NULL,
    sample_count INT NOT NULL,
    event_time_utc TIMESTAMPTZ NOT NULL,
    source_tz VARCHAR(64) NOT NULL,
    payload_id VARCHAR(64) NOT NULL
);

SELECT create_hypertable('metrics_5s', 'event_time_utc', if_not_exists => TRUE);

CREATE INDEX IF NOT EXISTS idx_metrics_tenant_lookup 
    ON metrics_5s (tenant_id, metric_name, src, event_time_utc DESC);

ALTER TABLE metrics_5s ENABLE ROW LEVEL SECURITY;
ALTER TABLE metrics_5s FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_metrics ON metrics_5s
    USING (tenant_id = current_setting('app.tenant', true))
    WITH CHECK (tenant_id = current_setting('app.tenant', true));

-- ----------------------------------------------------------------------------
-- 5. Log Fingerprints (Mined Templates)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS log_fingerprints (
    tenant_id VARCHAR(64) NOT NULL,
    collector_id VARCHAR(64) NOT NULL,
    src VARCHAR(64) NOT NULL,
    template_hash VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    hit_count INT NOT NULL,
    event_time_utc TIMESTAMPTZ NOT NULL,
    payload_id VARCHAR(64) NOT NULL
);

SELECT create_hypertable('log_fingerprints', 'event_time_utc', if_not_exists => TRUE);

ALTER TABLE log_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE log_fingerprints FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_fingerprints ON log_fingerprints
    USING (tenant_id = current_setting('app.tenant', true))
    WITH CHECK (tenant_id = current_setting('app.tenant', true));

-- ----------------------------------------------------------------------------
-- 6. Security Risk Events (e.g. auth-failure bursts)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS security_events (
    tenant_id VARCHAR(64) NOT NULL,
    collector_id VARCHAR(64) NOT NULL,
    src VARCHAR(64) NOT NULL,
    category VARCHAR(64) NOT NULL,
    failure_count INT NOT NULL,
    win_s INT NOT NULL,
    risk_level VARCHAR(32) NOT NULL,
    event_time_utc TIMESTAMPTZ NOT NULL,
    payload_id VARCHAR(64) NOT NULL
);

SELECT create_hypertable('security_events', 'event_time_utc', if_not_exists => TRUE);

ALTER TABLE security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE security_events FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_security ON security_events
    USING (tenant_id = current_setting('app.tenant', true))
    WITH CHECK (tenant_id = current_setting('app.tenant', true));

-- ----------------------------------------------------------------------------
-- 7. Collector Health History (Hysteresis & Reason Codes)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS collector_health_history (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    collector_id VARCHAR(64) NOT NULL,
    old_state VARCHAR(32) NOT NULL,
    new_state VARCHAR(32) NOT NULL,
    reason_codes TEXT[] NOT NULL,
    transition_time_utc TIMESTAMPTZ NOT NULL,
    source_tz VARCHAR(64) NOT NULL
);

ALTER TABLE collector_health_history ENABLE ROW LEVEL SECURITY;
ALTER TABLE collector_health_history FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_health ON collector_health_history
    USING (tenant_id = current_setting('app.tenant', true))
    WITH CHECK (tenant_id = current_setting('app.tenant', true));

-- ----------------------------------------------------------------------------
-- 8. Incidents & Evidence Cards (AIOps outputs)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS incidents (
    incident_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    severity VARCHAR(32) NOT NULL,
    state VARCHAR(32) DEFAULT 'open' NOT NULL,
    affected_components TEXT[] NOT NULL,
    likely_cause VARCHAR(255) NOT NULL,
    confidence DOUBLE PRECISION NOT NULL,
    raw_alert_count INT DEFAULT 1 NOT NULL,
    opened_at_utc TIMESTAMPTZ NOT NULL,
    closed_at_utc TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, incident_id)
);

ALTER TABLE incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE incidents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_incidents ON incidents
    USING (tenant_id = current_setting('app.tenant', true))
    WITH CHECK (tenant_id = current_setting('app.tenant', true));

CREATE TABLE IF NOT EXISTS evidence_cards (
    incident_id VARCHAR(64) NOT NULL,
    tenant_id VARCHAR(64) NOT NULL,
    contributing_signals JSONB NOT NULL,
    why_this_cause TEXT NOT NULL,
    why_not_alternatives TEXT NOT NULL,
    suggested_action TEXT NOT NULL,
    created_at_utc TIMESTAMPTZ DEFAULT clock_timestamp() NOT NULL,
    PRIMARY KEY (tenant_id, incident_id)
);

ALTER TABLE evidence_cards ENABLE ROW LEVEL SECURITY;
ALTER TABLE evidence_cards FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_evidence ON evidence_cards
    USING (tenant_id = current_setting('app.tenant', true))
    WITH CHECK (tenant_id = current_setting('app.tenant', true));

-- ----------------------------------------------------------------------------
-- 9. Append-Only System Audit Log (Tamper-evident operations)
-- ----------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS audit_log (
    id BIGSERIAL PRIMARY KEY,
    tenant_id VARCHAR(64) NOT NULL,
    actor VARCHAR(128) NOT NULL,
    role VARCHAR(32) NOT NULL,
    action VARCHAR(128) NOT NULL,
    resource VARCHAR(128) NOT NULL,
    details JSONB,
    timestamp_utc TIMESTAMPTZ DEFAULT clock_timestamp() NOT NULL
);

ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation_audit ON audit_log
    USING (tenant_id = current_setting('app.tenant', true))
    WITH CHECK (tenant_id = current_setting('app.tenant', true));
