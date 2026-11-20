-- VeilOps Local Collector SQLite Database Schema
-- Provides crash-safe WAL outbox, hash-chained egress ledger, and 24h rolling raw store.

PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- 1. Local Raw Telemetry Store (24-Hour Rolling Purge)
CREATE TABLE IF NOT EXISTS local_raw_store (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL,
    event_type TEXT NOT NULL,           -- 'syslog', 'pcap', 'auth', 'snmp'
    raw_payload TEXT NOT NULL,          -- Full unredacted data (for local-only diagnostics)
    captured_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL       -- captured_at + 24 hours
);

CREATE INDEX IF NOT EXISTS idx_raw_expires ON local_raw_store(expires_at);

-- 2. Reliable Outbox Buffer (At-Least-Once Delivery to SaaS)
CREATE TABLE IF NOT EXISTS outbox (
    payload_id TEXT PRIMARY KEY,        -- ULID / UUIDv7
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    seq INTEGER NOT NULL UNIQUE,        -- Contiguous sequence counter per collector
    payload_bytes BLOB NOT NULL,        -- Serialized canonical wire contract JSON bytes
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'SENT', 'ACKED', 'FAILED')),
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_error TEXT,
    sent_at TIMESTAMP,
    acked_at TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_outbox_queue ON outbox(status, next_retry_at);
CREATE INDEX IF NOT EXISTS idx_outbox_seq ON outbox(seq);

-- 3. Hash-Chained Egress Ledger (Tamper-Evident Proof Chain)
CREATE TABLE IF NOT EXISTS egress_ledger (
    seq INTEGER PRIMARY KEY,            -- Monotonically increasing sequence number
    payload_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    prev_hash TEXT NOT NULL,            -- SHA-256 hex digest of predecessor ledger row
    payload_hash TEXT NOT NULL,         -- SHA-256 hex digest of this payload_bytes
    payload_bytes BLOB NOT NULL,        -- Byte-for-byte exact outbound payload
    signature TEXT NOT NULL,            -- Ed25519 signature over canonical payload
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP,
    ack_status TEXT NOT NULL DEFAULT 'PENDING' CHECK(ack_status IN ('PENDING', 'ACKED')),
    saas_verified INTEGER NOT NULL DEFAULT 0 CHECK(saas_verified IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_ledger_payload ON egress_ledger(payload_id);
CREATE INDEX IF NOT EXISTS idx_ledger_hash ON egress_ledger(payload_hash);
