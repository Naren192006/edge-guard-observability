# VeilOps Tier 1: Collector & Privacy Technical Design Specification
## Phase 2 Architecture & System Design (Person 1 - Collector & Privacy Lead)

**Document Version**: 2.0  
**Phase**: Phase 2 Architecture & Technical Design (25 Marks)  
**Scope**: Tier 1 Local Collector Architecture, Egress Gate, Redaction Engine, SQLite WAL Outbox, Hash-Chained Ledger, and Telemetry Engine.

---

## 1. End-to-End Module Pipeline Diagram

The local collector operates inside the customer premises (Tier 1) as a sovereign container. Telemetry records pass sequentially through seven deterministic pipeline stages before crossing the untrusted network boundary to Tier 2 (Regional SaaS).

```mermaid
flowchart TD
    subgraph TIER1["Tier 1: Customer Site / Local Collector (Private Network)"]
        direction TB

        subgraph S1["Stage 1: Collect (asyncio Tasks)"]
            P_Host["psutil Input\n(CPU, Mem, Disk, Net)"]
            P_Net["ping3 / TCP Probes\n(Latency, Packet Loss)"]
            P_Syslog["Syslog Listener\n(UDP/TCP 514)"]
            P_Flow["Flow / Stream Adapter\n(NetFlow/IPFIX/Sim)"]
        end

        subgraph S2["Stage 2: Normalize (normalize.py)"]
            Norm["Internal Event Model\n- Event Time (UTC ISO 8601)\n- Source Timezone (IANA)\n- Metric / Event Struct"]
        end

        subgraph S3["Stage 3: Filter & Redact (redact.py)"]
            Redact["Redaction & Scrubbing Engine\n- Regex Secret Rules\n- Shannon Entropy Gate (>4.2)\n- Salted HMAC Pseudonyms (h_*, p_*)"]
            LocalVault[("Local Raw Store\n(Raw logs, PCAP, 24h rolling TTL)")]
            SaltFile[("Local HMAC Salt\n(chmod 0600 - Never Leaves Site)")]
            SaltFile -.-> Redact
            Norm -.->|Raw Archive Copy| LocalVault
        end

        subgraph S4["Stage 4: Aggregate (aggregate.py, fingerprint.py)"]
            Agg["5-Second Tumbling Windows\n(min, max, mean, p95, count)"]
            Drain["Drain3 Miner\n(Online Parse Tree -> Hex Template Hash)"]
        end

        subgraph S5["Stage 5: Local Analytics (analyze.py)"]
            LocalStats["Local Anomaly & Security Heuristics\n- EWMA / Robust Z-Scores\n- Sliding Auth-Failure Counter (risk: high)"]
        end

        subgraph S6["Stage 6: Apply Data Policy (egress_gate.py)"]
            Gate{"Egress Gate Check"}
            PolicyYAML["Signed Tenant Policy\n(allowed metrics, severities)"]
            CanaryScan["Canary & Entropy Tripwire\n(100% Outbound Byte Scan)"]
            Alarm["Local Security Alarm\n(leak_blocked counter ++)"]
            PolicyYAML -.-> Gate
            CanaryScan -.-> Gate
            Gate -.->|Tripwire Hit| Alarm
        end

        subgraph S7["Stage 7: Outbox & Transmit (outbox.py, sender.py)"]
            SignEngine["Ed25519 Signer\n(Signs Canonical Bytes)"]
            OutboxDB[("SQLite Outbox (WAL Mode)\n- Guaranteed At-Least-Once Buffer\n- Delete-After-Ack")]
            LedgerDB[("Hash-Chained Egress Ledger\n- prev_hash binding\n- Immutable Local Audit")]
            Sender["mTLS 1.3 Async Sender\n- Exponential Backoff + Jitter\n- Bounded Concurrency Drain"]
        end

        P_Host --> Norm
        P_Net --> Norm
        P_Syslog --> Norm
        P_Flow --> Norm

        Norm --> Redact
        Redact --> Agg
        Redact --> Drain
        Agg --> LocalStats
        Drain --> LocalStats
        LocalStats --> Gate
        Gate -->|Approved Metadata| SignEngine
        SignEngine --> OutboxDB
        SignEngine --> LedgerDB
        OutboxDB --> Sender
    end

    subgraph TRUST_BOUNDARY["=== TRUST BOUNDARY (Zero Raw Data Crosses) ==="]
        WirePayload["Typed Egress Wire Contract\n(contracts/payload.schema.json)\nadditionalProperties: false | No Free Text"]
    end

    subgraph TIER2["Tier 2: Regional SaaS Ingest (Metadata Only)"]
        Edge["Caddy mTLS Edge\n(Certificate Auth)"]
        FastAPI["FastAPI Ingest\n- Re-validate Schema\n- Verify Ed25519 Signature\n- Tenant Certificate Binding\n- Dedupe by payload_id"]
        Edge --> FastAPI
    end

    Sender -->|mTLS 1.3 / HTTPS POST| WirePayload
    WirePayload --> Edge
    FastAPI -.->|HTTP 200 Ack (payload_id)| OutboxDB

    classDef stage fill:#f1f8e9,stroke:#558b2f,stroke-width:1px;
    classDef boundary fill:#ffebee,stroke:#c62828,stroke-width:2px;
    classDef db fill:#ede7f6,stroke:#512da8,stroke-width:1px;
    classDef saas fill:#e1f5fe,stroke:#0277bd,stroke-width:2px;
    class S1,S2,S3,S4,S5,S6,S7 stage;
    class TRUST_BOUNDARY boundary;
    class OutboxDB,LedgerDB,LocalVault,SaltFile db;
    class TIER2 saas;
```

---

## 2. Wire Schema & Sample Validation Architecture

The wire schema defined in `contracts/payload.schema.json` strictly enforces:
- `additionalProperties: false` across all root and nested nodes.
- Strict bounded numeric fields, explicit enums, and regex patterns for identifiers.
- Complete exclusion of free-form string keys (`message`, `log`, `body`, `raw`, `payload`).

### Conformance Test Vectors Summary
1. **Valid Payload 1 (`contracts/samples/valid_payload_1.json`)**: Steady-state CPU metrics + Drain3 error fingerprint (`9f3a1c`) + auth failure risk indicator.
2. **Valid Payload 2 (`contracts/samples/valid_payload_2.json`)**: Multi-metric payload (CPU + Memory) + info logs + healthy state.
3. **Valid Payload 3 (`contracts/samples/valid_payload_3.json`)**: Network probe degradation (latency + packet loss) + port scan event + poor health state.
4. **Rejected Payload 1 (`contracts/samples/rejected_payload_1_free_text.json`)**: Fails with `Root object has unpermitted property: 'message'`.
5. **Rejected Payload 2 (`contracts/samples/rejected_payload_2_unknown_field.json`)**: Fails with `Root object has unpermitted property: 'raw_ip'`.
6. **Rejected Payload 3 (`contracts/samples/rejected_payload_3_invalid_enum.json`)**: Fails with `Metric[0] name 'unauthorized_arbitrary_metric' is not in allowed enum`.

---

## 3. Redaction Rule-Pack Specification

The collector redacts sensitive tokens before aggregation using a multi-layered defense:

### A. Regex Rule Pack for Secrets
| Pattern Name | Target Signature | Regular Expression | Action |
| :--- | :--- | :--- | :--- |
| `api_key_aws` | AWS Access Key ID | `(?<![A-Z0-9])[A-Z0-9]{20}(?![A-Z0-9])` | Mask with `[REDACTED_AWS_KEY]` / Drop |
| `api_key_stripe` | Stripe Live/Test Secret | `(?i)sk_(?:live\|test)_[0-9a-zA-Z]{24,}` | Mask with `[REDACTED_STRIPE_KEY]` / Drop |
| `jwt_token` | JSON Web Token | `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}` | Mask with `[REDACTED_JWT]` / Drop |
| `password_kv` | Password in URI or form | `(?i)(password\|passwd\|pwd\|secret\|token)\s*[:=]\s*["']?([^&\s"']+)` | Replace value with `[REDACTED_SECRET]` |
| `ipv4_address` | IPv4 address | `\b(?:(?:25[0-5]\|2[0-4][0-9]\|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]\|2[0-4][0-9]\|[01]?[0-9][0-9]?)\b` | Convert to `p_[hash]` via Salted HMAC |
| `username_pam` | Unix PAM user failure | `(?i)(?:user\|user\s*=|for\s*user)\s*['"]?([a-zA-Z0-9._-]+)['"]?` | Convert to `p_[hash]` via Salted HMAC |
| `email_address`| RFC 5322 Email | `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z\|a-z]{2,7}\b` | Mask with `[REDACTED_EMAIL]` / Drop |
| `card_pan` | 13-19 Digit Card + Luhn | `\b(?:\d{4}[-\s]?){3}\d{4}\b\|\b\d{13,19}\b` | Verify Luhn; replace with `[REDACTED_PAN]` |

### B. Shannon Entropy Calculation & Tuning
Tokens with high information density that escape regex rules (e.g. random base64 secrets, encryption keys) are captured via Shannon Entropy:
$$H(S) = -\sum_{i=1}^{n} P(c_i) \log_2 P(c_i)$$
- **Tuning Threshold**: $H \ge 4.2 \text{ bits/character}$ on string tokens longer than 16 characters.
- **Natural Language & Hex Baselines**: Standard English prose ($H \approx 2.8 - 3.4$), hexadecimal dumps ($H \approx 3.2 - 3.8$).
- **Trigger**: Any token with length $\ge 16$ and $H \ge 4.2$ is automatically scrubbed as `[HIGH_ENTROPY_TOKEN]` and halts egress.

### C. Salted HMAC Pseudonym Function
$$\text{Pseudonym}(\text{RawID}, \text{prefix}) = \text{prefix} \parallel \text{Hex}(\text{HMAC-SHA256}(\text{Salt}, \text{RawID}))[0:6]$$
- **Salt Generation**: 256-bit cryptographically secure random bytes (`os.urandom(32)`) initialized once at install time in `/etc/veilops/collector.salt` (`chmod 0600`).
- **Entity Prefixes**: `h_` for host/node instances (`h_4af29c`), `p_` for users/client IPs (`p_77d1`).
- **Properties**: Stable and deterministic correlation across time; computationally irreversible outside customer premises.

### D. Per-Tenant Policy YAML Format (`contracts/sample_policy.yaml`)
```yaml
tenant_id: "t_acme"
policy_v: 12
allowed_metrics:
  - cpu_pct
  - mem_pct
  - disk_pct
  - net_in_bytes
  - net_out_bytes
  - latency_ms
  - packet_loss_pct
  - tcp_retrans_pct
  - conn_active
allowed_severities:
  - warn
  - error
  - critical
max_fingerprints_per_window: 500
salt_rotation_interval_days: 90
```

---

## 4. SQLite DDL: Outbox & Hash-Chained Egress Ledger

The collector employs an ACID-compliant local SQLite database in **WAL mode** (`PRAGMA journal_mode=WAL;`).

```sql
-- SQLite Local Buffer & Tamper-Evident Ledger Schema
PRAGMA journal_mode = WAL;
PRAGMA synchronous = NORMAL;
PRAGMA foreign_keys = ON;

-- 1. Local Raw Store (24-Hour Rolling Retention Vault)
CREATE TABLE IF NOT EXISTS local_raw_store (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id TEXT NOT NULL,
    event_type TEXT NOT NULL,           -- 'syslog', 'pcap', 'auth'
    raw_payload TEXT NOT NULL,          -- Full unredacted data (for on-prem debugging)
    captured_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL       -- captured_at + 24 hours
);
CREATE INDEX IF NOT EXISTS idx_raw_expires ON local_raw_store(expires_at);

-- 2. Reliable Outbox Buffer (At-Least-Once Delivery)
CREATE TABLE IF NOT EXISTS outbox (
    payload_id TEXT PRIMARY KEY,        -- ULID / UUIDv7
    tenant_id TEXT NOT NULL,
    collector_id TEXT NOT NULL,
    seq INTEGER NOT NULL UNIQUE,        -- Contiguous sequential counter
    payload_bytes BLOB NOT NULL,        -- Serialized canonical JSON bytes
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'PENDING' CHECK(status IN ('PENDING', 'SENT', 'ACKED', 'FAILED')),
    retry_count INTEGER NOT NULL DEFAULT 0,
    next_retry_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_error TEXT,
    sent_at TIMESTAMP,
    acked_at TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_outbox_queue ON outbox(status, next_retry_at);

-- 3. Hash-Chained Egress Ledger (Tamper-Evident Proof Chain)
CREATE TABLE IF NOT EXISTS egress_ledger (
    seq INTEGER PRIMARY KEY,            -- Monotonic block sequence
    payload_id TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    prev_hash TEXT NOT NULL,            -- SHA-256 of preceding ledger block
    payload_hash TEXT NOT NULL,         -- SHA-256 of payload_bytes
    payload_bytes BLOB NOT NULL,        -- Exact outbound payload bytes
    signature TEXT NOT NULL,            -- Ed25519 digital signature
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    sent_at TIMESTAMP,
    ack_status TEXT NOT NULL DEFAULT 'PENDING' CHECK(ack_status IN ('PENDING', 'ACKED')),
    saas_verified INTEGER NOT NULL DEFAULT 0 CHECK(saas_verified IN (0, 1))
);
CREATE INDEX IF NOT EXISTS idx_ledger_payload ON egress_ledger(payload_id);
```

---

## 5. Telemetry Ingestion & Aggregation Plan

| Signal / Metric | Input Library | Polling Interval | Aggregation Method | Wire Enum Name | Unit / Range |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **CPU Utilization** | `psutil.cpu_percent` (per-core & total) | 1.0 second | 5-second tumbling window: `mean`, `p95`, `max`, `min` | `cpu_pct` | % ($0.0 - 100.0$) |
| **Memory Usage** | `psutil.virtual_memory().percent` | 1.0 second | 5-second tumbling window: `mean`, `p95`, `max` | `mem_pct` | % ($0.0 - 100.0$) |
| **Disk Space** | `psutil.disk_usage('/').percent` | 5.0 seconds | Instantaneous 5-second sample: `mean`, `max` | `disk_pct` | % ($0.0 - 100.0$) |
| **Network Bandwidth In**| `psutil.net_io_counters().bytes_recv` | 1.0 second | Delta per second: `mean`, `max` | `net_in_bytes` | Bytes/s ($0 - 10^9$) |
| **Network Bandwidth Out**| `psutil.net_io_counters().bytes_sent` | 1.0 second | Delta per second: `mean`, `max` | `net_out_bytes` | Bytes/s ($0 - 10^9$) |
| **Network Latency** | `ping3` / Async TCP Socket connect time | 2.5 seconds | 5-second window: `mean`, `p95`, `max` | `latency_ms` | Milliseconds ($0.0 - 10000.0$) |
| **Packet Loss** | ICMP echo sequence response tracking | 5.0 seconds (10 probes) | Window ratio: $(\text{lost} / \text{total}) \times 100$ | `packet_loss_pct` | % ($0.0 - 100.0$) |
| **Network Connectivity**| TCP handshake probe to regional gateway | 5.0 seconds | Binary status + TCP retransmission rate | `tcp_retrans_pct` | % ($0.0 - 100.0$) |
| **Syslog Feeds** | Asyncio UDP/TCP socket listener (port 514) | Event-driven | Drain3 online tree parser $\rightarrow$ Hex template hash + count | `log_fingerprints` | Hex hash (`9f3a1c`) + count |
| **Failed Logins** | Regex matching `/var/log/auth.log` | Event-driven | 60s sliding window count + source pseudonym + risk score | `security` | Count + risk enum (`high`) |

---

## 6. Bonus Architecture: Security, Retention & Auditing

### A. Canary Tripwire Design
1. **Canary Token Seeding**: The simulator deposits artificial honey-tokens into log feeds (e.g. `CANARY_AKIA_IOSFODNN7EXAMPLE`, `CANARY_PASSWD_SECRET999!`, `CANARY_JWT_EYJHB...`).
2. **Byte-Level Pre-Egress Inspection**: Immediately before an HTTP/mTLS payload leaves the collector container, the Egress Gate executes a substring and regex inspection of 100% of the UTF-8 serialized byte array against registered canary tokens.
3. **Hard-Block & Alarm**: If a canary token or high-entropy unredacted token is discovered:
   - Transmission is immediately aborted.
   - The payload is dropped into a quarantine isolation directory.
   - Local counter `leak_blocked` is incremented.
   - A critical security alarm is displayed on the local Egress Proof Panel.

### B. Local Retention 24-Hour Rolling Purge
- Raw logs and packets stored in `local_raw_store` carry an explicit `expires_at = datetime.utcnow() + timedelta(hours=24)`.
- A dedicated background asyncio worker executes an hourly vacuum cycle:
  ```sql
  DELETE FROM local_raw_store WHERE expires_at < CURRENT_TIMESTAMP;
  PRAGMA wal_checkpoint(TRUNCATE);
  ```
- This ensures sensitive raw diagnostic telemetry is erased automatically without operator intervention.

### C. Auditable Data-Transfer Record Format
For every transmission cycle, an auditable receipt is logged to `egress_ledger`:
```json
{
  "transfer_id": "xfer_01JD8Z3K7Q9X4M2V6T1B5N8R0C",
  "seq": 88412,
  "tenant_id": "t_acme",
  "collector_id": "c_blr_dc1",
  "timestamp_utc": "2026-11-20T09:15:05Z",
  "payload_sha256": "5f4dcc3b5aa765d61d8327deb882cf992b9599b422a00c6d70bc7646a5a2283a",
  "prev_hash": "b7c1048b6245ad689a72132e0cf0d64a85493b82937e0c03417531735d4ee90a",
  "byte_size": 1420,
  "fields_redacted_count": 8,
  "fields_dropped_count": 14,
  "signature": "ed25519:v1d0mN4K7+sB9x2LQe03p17qO/6dK6Fh5v42QdE8l0uW=",
  "saas_ack_status": "CONFIRMED",
  "saas_ack_hash": "5f4dcc3b5aa765d61d8327deb882cf992b9599b422a00c6d70bc7646a5a2283a"
}
```
Verification is achieved when `payload_sha256 == saas_ack_hash`, mathematically proving zero cloud tampering.
