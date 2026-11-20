# VeilOps: Phase 4 — SaaS & Reliability Final Demo Runbook, Verification Scripts & Judge Defense

**Role:** Person 2 (SaaS and Reliability Lead)  
**Hackathon:** CICADA 2026 (24-Hour Hackathon)  
**Track:** Secure AIOps Observability Solution  
**Phase Evaluation Weight:** Final Demo, Validation & Presentation (30 Marks)

---

## 1. Scenario 2 Runbook: Collector Loses SaaS Connectivity (Forced 90s Outage Drill)

This scenario demonstrates that during network disruptions or regional SaaS outages:
1. The collector buffers all telemetry locally in its SQLite WAL outbox with zero dropped metrics.
2. The SaaS watchdog detects the missing 10s heartbeats, downgrades health to `Fair` (`STALE_DATA`) at 15s, and `Poor` (`COLLECTOR_OFFLINE`) at 60s.
3. Upon reconnection at 90s, the collector drains its backlog oldest-first with bounded concurrency ($N=5$).
4. The SaaS reconciles sent-versus-received payload IDs, proving **strictly zero data loss and zero duplicates**.

### Step-by-Step Execution Guide

| Step | Time Offset | Action / Command | Expected System Behavior | What the Judges See |
| :---: | :---: | :--- | :--- | :--- |
| **1** | $T = 0\text{s}$ | `python simulator/scenario_injector.py --scenario steady_state` | Collector transmits 5s metric windows; SaaS receives payloads normally. | Fleet status: **`EXCELLENT`** (Reason: `NOMINAL`), outbox depth: 0, Latency: $\sim 350\text{ms}$. |
| **2** | $T = 10\text{s}$ | `python simulator/scenario_injector.py --scenario inject_outage --duration 90s` *(or block port 8000/8443)* | SaaS Ingest becomes unreachable. Collector 3s ACK timer times out. | Collector marks link down. Payloads written to local SQLite WAL outbox. |
| **3** | $T = 25\text{s}$ | *(Watch SaaS Dashboard)* | $15\text{s}$ without heartbeats triggers watchdog threshold. | Health badge transitions to **`FAIR`** (Reason: `STALE_DATA`). Event history logs transition. |
| **4** | $T = 70\text{s}$ | *(Watch SaaS Dashboard)* | $60\text{s}$ without heartbeats triggers offline threshold. | Health badge transitions to **`POOR`** (Reason: `COLLECTOR_OFFLINE`). Alarm counter increments. |
| **5** | $T = 85\text{s}$ | `curl http://localhost:5000/api/outbox/status` | Outbox accumulates payloads locally ($18\text{ windows}$). | Outbox Depth: **18 payloads queued** in SQLite WAL. Zero dropped. |
| **6** | $T = 100\text{s}$ | `python simulator/scenario_injector.py --scenario restore_link` | Network restored. Collector health probe succeeds. | Collector initiates ordered drain oldest-first (concurrency $N=5$). |
| **7** | $T = 110\text{s}$ | `python saas/reliability/audit_reconciliation.py --tenant t_acme` | SaaS deduplicates ULID/UUIDv7 keys; backfills historical chunks by `event_time_utc`. | **Reconciliation Report:**<br/>`Sent: 20 | Received: 20 | Lost: 0 | Duplicates: 0`<br/>Status: **`VERIFIED ZERO LOSS ZERO DUP`**. |
| **8** | $T = 125\text{s}$ | *(Watch SaaS Dashboard)* | 3 consecutive healthy windows arrive. Hysteresis clears alarm. | Health recovers: `Poor` $\to$ `Excellent`. Timeline preserves outage gap without rewriting historical timestamps. |

---

## 2. Latency & Target Benchmark Measurement Script
Proves real-time targets from shared stream timestamps:
- **Target 1:** Collection to dashboard within **$10\text{s}$ at $p_{95}$**.
- **Target 2:** Threshold breach to alert within **$15\text{s}$**.
- **Target 3:** Offline detection within **$60\text{s}$**.
- **Target 4:** Backlog delivery with **$0$ loss and $0$ duplicates**.

*(Implemented in `saas/reliability/measure_targets.py`)*

---

## 3. Tenant Isolation & Region Residency Proof Walkthrough

### 3.1 Live Tenant Isolation (PostgreSQL Row-Level Security Probe)
To prove to the judges that cross-tenant data leaks are mathematically impossible:

1. **Query as Tenant A (`t_acme`):**
   ```bash
   curl "http://localhost:8000/api/v1/metrics?tenant_id=t_acme&limit=10"
   ```
   *Expected Output:* Returns 10 telemetry rows belonging to `t_acme`.

2. **Query as Tenant B (`t_globex`) Attempting to Read Tenant A Data:**
   ```bash
   curl "http://localhost:8000/api/v1/metrics?tenant_id=t_globex&limit=10"
   ```
   *Expected Output:*
   ```json
   {
     "tenant_id": "t_globex",
     "count": 0,
     "metrics": [],
     "rls_status": "ENFORCED",
     "message": "Zero rows accessible from tenant t_acme. PostgreSQL RLS isolation verified."
   }
   ```

### 3.2 Region Residency Verification
- `t_acme` collector is provisioned with `home_region: ap-south`. All hypertable chunks and Redis streams are homed strictly in the `ap-south` PostgreSQL cluster (`veilops_ap_south`).
- `t_globex` collector is homed in `eu-central` (`veilops_eu_central`).
- The Global Control plane stores only tenant metadata and public cert fingerprints—**zero telemetry or logs cross regional boundaries**.

---

## 4. Live Demo Fallback Plan (Recorded Snapshot & Seeded Telemetry Run)

If live port bindings, docker networks, or conference Wi-Fi fail during the judging evaluation:

1. **Local Static Snapshot Mode:**  
   Execute the offline demo runner:
   ```bash
   python saas/reliability/run_reliability_demo.py --offline-fallback
   ```
   Loads a pre-recorded, cryptographically signed 100-payload telemetry run and replays the 90s outage and RLS isolation tests in deterministic memory mode.
2. **Pre-Seeded Database State:**  
   The database initialization script (`saas/db/init.sql`) automatically provisions:
   - 2 tenants: `t_acme` (`ap-south`) and `t_globex` (`eu-central`).
   - 2 collectors: `c_blr_dc1` and `c_fra_dc2`.
   - Seeded metric baselines and historical health transitions.

---

## 5. Concise Answers to Judge Questions (Max 3 Sentences Each)

### Q1: What happens when the SaaS is unreachable?
> **Answer:**  
> When the regional SaaS endpoint is unreachable or fails to acknowledge within 3 seconds, the collector immediately diverts all signed, schema-validated payloads into its local SQLite WAL outbox with contiguous sequence numbers. Tier 1 continues sampling, template mining, and local alert evaluation autonomously, while probing the regional endpoint with randomized, jittered exponential backoff ($1\text{s}$ to $30\text{s}$). Once connectivity returns, the collector drains the outbox oldest-first with bounded concurrency ($N=5$) to avoid overwhelming SaaS ingest.

### Q2: How are data loss and duplicate records prevented during an outage?
> **Answer:**  
> Every payload is stamped with a monotonic, collision-free ULID/UUIDv7 `payload_id` and an incremental sequence number per collector. The SaaS enforces a database-level unique index on `(tenant_id, payload_id)`: new records are ingested and processed, while retried duplicate payloads are safely recognized, acknowledged with `duplicate: true`, and rejected from re-insertion. Rows in the collector's SQLite outbox are deleted strictly after receiving this cryptographically validated acknowledgment from the SaaS.

### Q3: How does the SaaS platform scale to handle thousands of collectors and tenants?
> **Answer:**  
> The Ingest API is completely stateless and scales horizontally behind mTLS-terminating load balancers without shared in-memory state. Ingested payloads are queued into Redis Streams partitioned by tenant ID (`tenant:{id}:telemetry:stream`), allowing distributed consumer groups to parallelize storage and AIOps reasoning independently. Persistent time-series data is stored in TimescaleDB hypertables partitioned by tenant and 1-day time chunks, with native columnar compression delivering over $85\%$ storage reduction.

### Q4: How are regional residency, UTC timestamps, and out-of-order events handled?
> **Answer:**  
> Each tenant is bound to a single home region during onboarding, and all telemetry remains physically confined to that region's database; the global control plane holds zero telemetry. Every payload transmits `event_time_utc` stored as `TIMESTAMPTZ` alongside `source_tz` (e.g. `Asia/Kolkata`), while UI dashboards localize timestamps for operators. Out-of-order records are placed into their exact historical hypertable chunks by event time, with a 2-minute streaming watermark triggering window recomputations without overwriting observed collector outage history.

---

## 6. Honest Limitations & Production Readiness Roadmap

| Limitation in Hackathon Prototype | Real-World Impact | What Production VeilOps Would Need |
| :--- | :--- | :--- |
| **Single Redis Node** | Stream queuing has a single point of failure within each region. | Redis Sentinel or Redis Enterprise Cluster with Multi-AZ replication; Kafka or NATS JetStream for high-throughput enterprise tiers. |
| **Simplified Certificate Authority** | Collector mTLS certificates are issued using static self-signed or mkcert CAs. | Automated HashiCorp Vault or `step-ca` PKI integration with ACME protocol, hardware TPM/HSM key storage on collectors, and automated CRL/OCSP stapling. |
| **No Multi-Region Disaster Recovery** | An entire cloud region failure requires manual DNS failover to an alternate region. | Active-passive cold standby regional database replication with audited cryptographic policy approval and automated geo-DNS failover. |
| **In-Memory Buffer Size Cap** | Outbox disk capping defaults to 1 GB before coarsening 5s windows into 1-minute summaries. | Dynamic NVMe disk-spooling with customer-configurable retention policies (e.g., 7 days offline buffer). |

---

## 7. Bonus: 30-Second Global-Ready Delivery Script (Replay & Shuffled Order)

*(Interactive demo script demonstrating out-of-order event placement and duplicate idempotency in $<30$ seconds)*

```bash
python saas/reliability/run_reliability_demo.py --demo-global-delivery
```

**Demonstration Script Narrative:**
1. **[00:00 - 00:10] Shuffled Ingestion:**  
   Three payloads with event timestamps $T_1$, $T_2$, and $T_3$ are injected in reverse order: $[T_3, T_1, T_2]$. The SaaS places each row into TimescaleDB by `event_time_utc`, showing that time-series queries return perfectly ordered chronological data.
2. **[00:10 - 00:20] Replayed Duplicates:**  
   The identical three payloads are retransmitted to simulate network ACK packet loss. The Ingest API detects matching `(tenant_id, payload_id)` keys, returns HTTP 200 `duplicate=True`, and suppresses duplicate stream writes.
3. **[00:20 - 00:30] Proof Panel Verification:**  
   The reconciliation panel renders: `Total Sent: 6 | Total Stored: 3 | Duplicates Suppressed: 3 | Gaps: 0 | Status: VERIFIED`.
