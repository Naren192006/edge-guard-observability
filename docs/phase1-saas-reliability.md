# Phase 1: SaaS Architecture and Reliability Blueprint
**Role:** Person 2 — SaaS and Reliability Architect  
**Project:** VeilOps (Secure AIOps Observability Platform)  
**Hackathon:** CICADA 2026 — 24-Hour Hackathon  
**Target Window:** Hours 0 to 4 (Phase 1: Problem Understanding & Ideation — 10 Marks)

---

## 1. Who-Can-See-What RBAC Matrix & Tenant Separation

VeilOps enforces strict zero-trust tenant isolation and role-based access control (RBAC). No tenant can ever observe or query telemetry, alerts, or audit trails from another tenant, even in shared multi-tenant database infrastructure.

### 1.1 RBAC Matrix

| Resource / Capability | Viewer | Operator | Admin | Auditor |
| :--- | :---: | :---: | :---: | :---: |
| **Telemetry & Metrics** (CPU, Mem, Disk, Latency, Loss) | Read-only | Read-only | Full Access | No Access (Privacy Guard) |
| **Collector Fleet Health & Status** | View State | View + Ack | Full Config | View State & Health History |
| **Alerts & Incidents** | View Open | View, Ack, Triage | Manage & Close | View Historical Log |
| **AIOps Evidence Cards** | View Cards | View & Investigate | Full Access | View Reasoning Trail |
| **Tenant Data Policy** (Metrics allow-list, drops) | Read-only | Read-only | Create / Edit / Sign | Read-only |
| **Automated Remediation Actions** | No Access | Propose Runbook | Approve & Execute | View Execution Audit Log |
| **Egress Ledger & Hashes** (Tamper-evident chain) | No Access | Verify Hash | Verify & Manage | Full Audit & Verification |
| **Append-Only System Audit Log** | No Access | No Access | Read Audit Log | Full Read & Export |
| **Cryptographic Certificates & API Keys** | No Access | No Access | Issue / Revoke | Verify Public Keys |

> **Key Architectural Insight:** Notice the `auditor` role. An auditor has zero access to raw telemetry metrics, yet has full, unhindered access to the cryptographic egress ledger, hash chains, and the immutable audit log. Conversely, a `viewer` can monitor service health but cannot view cryptographic ledger internals or security incident approvals.

---

### 1.2 Tenant Separation Enforcement

Tenant isolation in VeilOps is enforced across four distinct layers to guarantee defense-in-depth:

```
[ Inbound Request ] 
        │ (JWT / mTLS Cert with verified SAN: tenant_id)
        ▼
┌────────────────────────────────────────────────────────┐
│ Layer 1: FastAPI Middleware Context Injection          │
│ - Extracts tenant_id strictly from authenticated token │
│ - Never trusts path, query, or body tenant_id          │
└───────────────────────┬────────────────────────────────┘
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
┌───────────────────────────┐   ┌───────────────────────────┐
│ Layer 2: Postgres RLS     │   │ Layer 3: Redis Partition  │
│ - SET LOCAL app.tenant    │   │ - Stream key prefixed:    │
│ - tenant_id = setting()   │   │   tenant:{id}:stream      │
│ - FORCE ROW LEVEL SEC     │   │ - Consumer group scoped   │
└───────────────────────────┘   └───────────────────────────┘
```

#### Layer 1: Database Row-Level Security (PostgreSQL 16 + TimescaleDB)
1. **Mandatory Column:** Every single relational table and TimescaleDB hypertable (`metrics_5s`, `log_fingerprints`, `security_events`, `incidents`, `evidence_cards`, `collector_health`, `audit_log`) has a non-nullable `tenant_id VARCHAR(64)` column.
2. **PostgreSQL RLS Policies:**
   ```sql
   ALTER TABLE metrics_5s ENABLE ROW LEVEL SECURITY;
   ALTER TABLE metrics_5s FORCE ROW LEVEL SECURITY;

   CREATE POLICY tenant_isolation_policy ON metrics_5s
       AS RESTRICTIVE
       USING (tenant_id = current_setting('app.tenant', true))
       WITH CHECK (tenant_id = current_setting('app.tenant', true));
   ```
3. **Session-Level Tenant Binding:** When an API request or worker opens a database connection from the connection pool, the middleware extracts the cryptographically verified `tenant_id` from the JWT / mTLS certificate and executes:
   ```sql
   SET LOCAL app.tenant = 't_acme';
   ```
   Even if an attacker or buggy query executes `SELECT * FROM metrics_5s WHERE tenant_id = 't_globex'`, the PostgreSQL engine evaluates the RLS policy against `current_setting('app.tenant')` and returns **0 rows**.

#### Layer 2: In-Memory Streaming & Queuing (Redis Streams)
1. All Redis stream keys and pub/sub channels are strictly prefixed by tenant ID:
   - Telemetry Stream: `tenant:{tenant_id}:telemetry:stream`
   - Anomaly Alert Stream: `tenant:{tenant_id}:alerts:stream`
   - Incident Stream: `tenant:{tenant_id}:incidents:stream`
2. Consumer groups are configured per tenant, ensuring analytics workers for Tenant A never read from Tenant B's queue.

#### Layer 3: Cache Key Namespacing
1. Any intermediate caching (e.g., metric rollups, collector online states) uses namespaced keys:
   - `cache:{tenant_id}:collector:{collector_id}:status`
2. Eviction, invalidation, and reads are constrained to the tenant namespace.

---

## 2. Regional Ingest & Tenant Data-Residency Decisions

### 2.1 The Three Regions
VeilOps deploys regional cells to satisfy international data-sovereignty regulations (such as India DPDP, EU GDPR, US HIPAA/SOC2):
1. **`ap-south`** (Asia-Pacific / India — Mumbai / Bangalore): Default region for South Asian workloads; source timezone typically `Asia/Kolkata`.
2. **`eu-central`** (Europe — Frankfurt): GDPR-compliant cell with strict EU data residency guarantees.
3. **`us-east`** (North America — N. Virginia): High-throughput US cloud workload cell.

### 2.2 Regional Homing & Routing
- **Home Region Binding:** Each customer tenant is assigned a single **Home Region** at onboarding (e.g., `t_acme` $\to$ `ap-south`, `t_globex` $\to$ `eu-central`).
- **Collector Endpoint Configuration:** The local collector is configured with its home region ingest endpoint (`https://ingest.ap-south.veilops.internal/v1/telemetry`).
- **Complete Regional Isolation:** Ingest APIs, Redis Streams, TimescaleDB, and AIOps analytics engines run entirely within each regional cell. A tenant's telemetry metadata is stored **exclusively** in their home region database.

```
                              ┌───────────────────────────────────┐
                              │    Global Control Plane (Cloud)   │
                              │  - Tenant directory (ID -> Region)│
                              │  - Cert fingerprints & status     │
                              │  - Global IAM / SSO login         │
                              │  * ZERO TELEMETRY OR LOG DATA *   │
                              └─────────────────┬─────────────────┘
                                                │
                 ┌──────────────────────────────┼──────────────────────────────┐
                 │                              │                              │
                 ▼                              ▼                              ▼
      ┌─────────────────────┐        ┌─────────────────────┐        ┌─────────────────────┐
      │   Cell: ap-south    │        │  Cell: eu-central   │        │    Cell: us-east    │
      │ ┌─────────────────┐ │        │ ┌─────────────────┐ │        │ ┌─────────────────┐ │
      │ │ mTLS Edge Ingest│ │        │ │ mTLS Edge Ingest│ │        │ │ mTLS Edge Ingest│ │
      │ └────────┬────────┘ │        │ └────────┬────────┘ │        │ └────────┬────────┘ │
      │          ▼          │        │          ▼          │        │          ▼          │
      │ ┌─────────────────┐ │        │ ┌─────────────────┐ │        │ ┌─────────────────┐ │
      │ │  Redis Streams  │ │        │ │  Redis Streams  │ │        │ │  Redis Streams  │ │
      │ └────────┬────────┘ │        │ └────────┬────────┘ │        │ └────────┬────────┘ │
      │          ▼          │        │          ▼          │        │          ▼          │
      │ ┌─────────────────┐ │        │ ┌─────────────────┐ │        │ ┌─────────────────┐ │
      │ │  TimescaleDB    │ │        │ │  TimescaleDB    │ │        │ │  TimescaleDB    │ │
      │ │  (t_acme data)  │ │        │ │ (t_globex data) │ │        │ │ (t_megacorp)    │ │
      │ └─────────────────┘ │        │ └─────────────────┘ │        │ └─────────────────┘ │
      └─────────────────────┘        └─────────────────────┘        └─────────────────────┘
```

### 2.3 Global Control Plane: What It May & May Not Store

| Global Control Plane MAY Store | Global Control Plane MAY NOT Store |
| :--- | :--- |
| Tenant IDs, display names, and billing subscription tiers | **No Telemetry**: No metric values, means, p95s, or counts |
| Tenant Home Region mapping (`tenant_id -> home_region`) | **No Log Fingerprints**: No template IDs, hashes, or frequencies |
| Collector registration IDs and mTLS public certificate SHA256 fingerprints | **No Security Indicators**: No auth failure counts or risk scores |
| Global user accounts, hashed credentials, and SSO identity bindings | **No Topology Graphs**: No node, edge, or network flow pseudonyms |
| Regional API endpoint directory URLs | **No Incident Details**: No evidence cards, cause rankings, or alerts |
| Global revocation lists for decommissioned collectors | **No Egress Hashes**: Tamper-evident ledgers stay within the regional cell |

---

## 3. Global Design Decisions

### 3.1 UTC Event Time Plus Source Timezone
* **Wire Contract Requirement:** Every payload transmits two mandatory temporal attributes:
  * `event_time_utc`: ISO 8601 UTC timestamp with millisecond resolution (e.g., `2026-11-20T09:15:05.120Z`).
  * `source_tz`: IANA timezone identifier representing the collector site (e.g., `Asia/Kolkata`, `Europe/Berlin`, `America/New_York`).
* **Database Representation:** All time-series tables in TimescaleDB store timestamps as `TIMESTAMPTZ` in UTC to guarantee consistent windowing, cross-region queryability, and mathematical correctness in AIOps models.
* **Viewer Contextualization:** The SaaS UI converts timestamps to the viewer's local browser timezone for operational convenience, while displaying `source_tz` on incident cards to enable correlation with physical site operations (e.g. shifts, scheduled maintenance windows, nightly batch processing).

### 3.2 Event-Time Ordering with a 2-Minute Watermark
* **Streaming Reasoner Invariant:** All analytics, anomaly baselines, and health evaluations operate on **event time** (`event_time_utc`), not ingest wall-clock arrival time.
* **Watermark Mechanism:** The AIOps stream consumer maintains a rolling high-watermark:
  $$\text{Watermark} = \max(\text{event\_time\_utc}) - 120\text{ seconds}$$
* **Late Data Handling:** 
  * Records arriving within the 2-minute watermark are integrated into their respective 5-second tumbling windows seamlessly.
  * Records arriving older than 2 minutes (e.g. following a restored network partition) are inserted into TimescaleDB historical hypertables and trigger an asynchronous **window recomputation** for the affected time intervals without rewriting the observed outage event in the collector health timeline.

### 3.3 Idempotent Delivery by `payload_id`
* **ULID / UUIDv7 Identifier:** Each payload generated by Tier 1 is tagged with a globally unique, time-ordered `payload_id` (e.g., `01JD8Z3K7Q9X4M2V6T1B5N8R0C`).
* **Storage Deduplication Index:** TimescaleDB enforces a primary / unique index on `(tenant_id, payload_id)`.
* **Two-Tier Ack Contract:**
  1. If `(tenant_id, payload_id)` is seen for the first time: Ingest API validates schema and signature, writes to Redis Streams, stores in TimescaleDB, and returns `HTTP 200 {"status": "ACK", "payload_id": "...", "duplicate": false}`.
  2. If `(tenant_id, payload_id)` already exists (caused by network timeout on previous ACK): Ingest API detects duplicate, suppresses duplicate queue publishing, and immediately returns `HTTP 200 {"status": "ACK", "payload_id": "...", "duplicate": true}`.
* **Collector Action:** The collector safely deletes the buffered payload from its SQLite outbox upon receiving the ACK, guaranteeing **at-least-once delivery over the wire** and **strictly exactly-once state mutation in the SaaS**.

---

## 4. Real-Time Target Verification & Measurement Plan

The hackathon evaluation sheet scores real-time reliability and performance through empirical verification against the shared telemetry stream.

```
[ Collector Event Created ] (t_event)
            │
            ▼ (5s window flush)
[ Ingest API Received ]     (t_ingest)
            │
            ▼ (Redis Streams)
[ AIOps Engine / DB ]       (t_process)
            │
            ▼ (SSE Push)
[ Dashboard Rendered ]      (t_render)
```

### 4.1 Target 1: Collection to Dashboard within 10s at p95
* **Target:** Real-time latency $\Delta t \le 10\text{s}$ at the 95th percentile.
* **Measurement Equation:**
  $$\Delta t_{\text{dashboard}} = t_{\text{dashboard\_render}} - t_{\text{event\_time\_utc}}$$
* **Implementation Plan:**
  1. The collector stamps `event_time_utc` upon closing each 5-second sampling window.
  2. The SaaS Ingest API records `ingest_time_utc` and publishes to Redis Streams.
  3. SaaS SSE (Server-Sent Events) pushes the processed metric event directly to the React frontend.
  4. The frontend captures `performance.now() / Date.now()`, computes $\Delta t_{\text{dashboard}}$, and pushes the latency sample into an in-memory reservoir histogram.
  5. The UI renders a live **Latency Histogram Widget** displaying rolling $p_{50}$, $p_{95}$, and $p_{99}$ metrics to the judges.

### 4.2 Target 2: Threshold Breach to Alert within 15s
* **Target:** Alert creation within 15s of an injected anomaly or threshold breach.
* **Measurement Equation:**
  $$\Delta t_{\text{alert}} = t_{\text{alert\_created}} - t_{\text{spike\_injected}}$$
* **Implementation Plan:**
  1. The scenario injector CLI tags an injected fault with an exact microsecond timestamp $t_{\text{spike\_injected}}$.
  2. The collector evaluates metrics in 5s windows; upon breaching baseline or critical bounds, an alert payload is dispatched immediately.
  3. The AIOps stream consumer generates an incident and stamps `t_alert_created`.
  4. The Incident Card header explicitly prints:
     ```
     Breach Injected: 09:14:40.000 UTC
     Alert Triggered: 09:14:51.420 UTC
     Detection Latency: 11.42s (Pass: < 15s)
     ```

### 4.3 Target 3: Offline Detection within 60s
* **Target:** Mark collector state as `Poor` (Reason: `COLLECTOR_OFFLINE`) within 60s of silence.
* **Implementation Plan:**
  1. Normal collector emits a heartbeat payload every 10 seconds.
  2. SaaS background watchdog task runs every 5 seconds, evaluating:
     $$\Delta t_{\text{silence}} = t_{\text{current}} - t_{\text{last\_heartbeat}}$$
  3. **State Transition Rules:**
     - $\Delta t_{\text{silence}} \le 15\text{s}$: State remains `Excellent` or `Good`.
     - $15\text{s} < \Delta t_{\text{silence}} \le 60\text{s}$: Downgraded to `Fair` (Reason: `STALE_DATA`).
     - $\Delta t_{\text{silence}} > 60\text{s}$: Downgraded to `Poor` (Reason: `COLLECTOR_OFFLINE`).
  4. Watchdog writes state change event to `collector_health_history` with old state, new state, reason code, and timestamp.
  5. Dashboard updates health badge to red within $<60\text{s}$ of link severance.

### 4.4 Target 4: Zero Loss and Zero Duplicates
* **Target:** Complete delivery of buffered backlog with zero lost payloads and zero duplicate records.
* **Implementation Plan:**
  1. The collector stamps each payload with a strictly monotonic sequence number `seq` per collector (`seq = 1, 2, 3, ...`) and a unique `payload_id`.
  2. During a 90-second link cutoff, the collector buffers all payloads in its SQLite outbox.
  3. The SaaS tracks `last_seen_seq` per collector and flags gap pending if sequence jumps.
  4. Upon reconnect, the collector drains its SQLite outbox oldest-first.
  5. The SaaS deduplication layer rejects duplicate insertions while acknowledging receipt.
  6. **Reconciliation Verification Tool:**
     - The SaaS query endpoint `/api/v1/collectors/{id}/reconciliation` computes:
       $$\text{Lost} = \text{Sent\_Count} - \text{Received\_Count} = 0$$
       $$\text{Duplicates\_Stored} = \text{Total\_Received} - \text{Unique\_Payload\_IDs} = 0$$
     - The UI renders the live verification badge: `Backlog Verified: 100% (Zero Loss, Zero Duplicates)`.

---

## 5. Bonus: Six-Line Outage and Reconnect Plan
*(Covering local buffering, graceful degradation, and global-ready delivery)*

1. **Detect & Buffer:** When SaaS ACK times out (>3s) or network link drops, Tier 1 immediately pauses transmission and writes all signed, schema-validated payloads to its local SQLite WAL outbox with contiguous `seq`.
2. **Local Autonomy:** Tier 1 collector continues sampling, Drain3 template mining, local baselines, and local alert evaluation uninterrupted, logging all records to its local store.
3. **SaaS Degradation:** SaaS watchdog detects missing 10s heartbeats, downgrading collector status to `Fair` (`STALE_DATA`) at 15s and `Poor` (`COLLECTOR_OFFLINE`) at 60s, preserving historical outage records.
4. **Exponential Probe:** Collector background sender probes the regional ingest endpoint using exponential backoff with jitter ($1\text{s} \to 2\text{s} \to 4\text{s} \dots 30\text{s}$) until network connectivity returns.
5. **Ordered Bounded Drain:** Upon connection re-establishment, sender drains buffered outbox rows oldest-first with bounded concurrency ($N=5$) to prevent overwhelming regional Ingest APIs.
6. **Reconcile & Purge:** SaaS idempotently ingests payloads via `payload_id`, places time-series by `event_time_utc`, acknowledges each payload, and Tier 1 deletes acknowledged rows from the SQLite outbox.

---

## 6. Integration Checklist & Next Phase Hand-Off

| Component | Owner | Hand-Off Artifact to Person 1 & Person 3 |
| :--- | :--- | :--- |
| **Contracts** | Person 1, 2, 3 | `contracts/payload.schema.json` (frozen at Hour 2) |
| **SaaS Deploy** | Person 2 | `deploy/docker-compose.yml` (multi-region AP & EU cells) |
| **Database DDL** | Person 2 | `saas/db/init.sql` (Postgres 16 + TimescaleDB + RLS) |
| **Ingest API** | Person 2 | `saas/ingest/` (FastAPI + Redis Streams + Idempotency) |
| **Collector Tier**| Person 1 | `collector/` (Inputs, Redact, Outbox, Proof Panel) |
| **AIOps & Web** | Person 3 | `saas/aiops/` & `web/` (Baselines, Evidence Cards, React) |
