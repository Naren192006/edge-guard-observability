# VeilOps: Secure AIOps Observability Solution

> **CICADA 2026 Hackathon** | **Two-Tier Privacy-by-Construction Observability & Explainable AIOps**

VeilOps is a two-tier AIOps observability platform in which raw telemetry physically cannot leave the customer site: the local collector turns everything into a typed, signed, metadata-only contract, and the SaaS reasons over that contract alone.

---

## 🗂️ Repository Structure & Ownership

```text
edge-guard-observability/
├── contracts/                         # Frozen wire schemas and validation suites [Shared / Person 1]
│   ├── payload.schema.json            # Strict JSON Schema (additionalProperties: false)
│   ├── policy.schema.json             # Tenant data policy schema
│   ├── sample_policy.yaml             # Example tenant egress policy
│   ├── sample_payload.json            # Valid sample payload conforming to contract
│   ├── validate_contracts.py          # Automated contract validation test runner
│   └── samples/                       # Conformance test vectors
│       ├── valid_payload_1.json       # Normal steady-state telemetry
│       ├── valid_payload_2.json       # High CPU & auth failure burst
│       ├── valid_payload_3.json       # Latency spike & error fingerprints
│       ├── rejected_payload_1_free_text.json    # Rejection: contains forbidden "message"
│       ├── rejected_payload_2_unknown_field.json # Rejection: contains unlisted "raw_ip"
│       └── rejected_payload_3_invalid_enum.json # Rejection: unapproved enum values
├── docs/                              # Architectural and phase documentation
│   ├── PHASE1_SECURITY_ARCHITECTURE.md # Person 1: Security & Privacy Architecture Spec
│   ├── phase1-saas-reliability.md      # Person 2: SaaS & Reliability Architecture Spec
│   ├── phase1_aiops_and_demo.md        # Person 3: Master Product, AIOps & Demo Spec
│   └── phase1_one_page_summary.md      # Person 3: One-page system & allow-list summary
├── collector/                         # Tier 1 Local Collector [Person 1: Collector & Privacy]
│   ├── inputs/                        # Telemetry plugins (psutil, ping/TCP, syslog, flow)
│   ├── normalize.py                   # UTC + source timezone mapping
│   ├── redact.py                      # Shannon entropy, regex rules, salted HMAC pseudonyms
│   ├── aggregate.py                   # 5-second tumbling windows
│   ├── fingerprint.py                 # Drain3 online log template mining
│   ├── egress_gate.py                 # Allow-list validation, Canary scan, Ed25519 signing
│   ├── outbox.py                      # SQLite WAL outbox, hash-chained ledger
│   └── ui/                            # FastAPI + HTMX Egress Proof Panel (Local)
├── saas/                              # Tier 2 SaaS Platform [Person 2: SaaS & Reliability]
│   ├── ingest/                        # FastAPI Regional Ingest API & Idempotency
│   │   └── main.py                    # Regional ingest endpoint with Ed25519 & schema recheck
│   ├── workers/                       # TimescaleDB writer, Stream consumers
│   ├── db/
│   │   ├── init.sql                   # Postgres 16 + TimescaleDB DDL + Row-Level Security (RLS)
│   │   └── migrations/
│   ├── api/                           # REST + SSE Query API for dashboards
│   └── tests/                         # SaaS Ingest & RLS test suite
├── saas/aiops/                        # AIOps Reasoning Engine [Person 3: AIOps & Demo]
│   ├── __init__.py
│   ├── baseline_prototype.py          # Phase 1 prototype: EWMA median/MAD + robust z-score
│   ├── baselines.py                   # Seasonal EWMA/MAD, Robust Z-Score, Half-Space Trees
│   ├── correlate.py                   # Topology graph (NetworkX) + Union-Find incident merging
│   ├── rank.py                        # Cause ranking (earliest onset, topology, blast radius)
│   └── recommendations.py             # Rule library & Evidence-Card generators
├── simulator/                         # Telemetry generator and scenario injector [Person 1 & 3]
│   ├── stream_adapter.py              # Simulated stream provider
│   └── scenario_injector.py           # Injects 8 judge scenarios
├── deploy/                            # Docker compose environments and certificates [Person 2]
│   ├── docker-compose.yml             # Multi-cell setup (ap-south, eu-central)
│   ├── caddy/                         # mTLS terminator configuration
│   └── certs/                         # Collector & Server mTLS certificates
├── web/                               # React + Vite + Tailwind + ECharts Dashboard [Person 2 & 3]
└── tests/                             # Automated test suite
    └── test_baseline_prototype.py      # Unit tests for AIOps baseline prototype
```

---

## 👥 3-Person Team Split & Responsibilities

| Member | Focus Area | Core Responsibilities |
| :--- | :--- | :--- |
| **Person 1** | Collector & Privacy Lead | Tier 1 collector, Redaction (entropy + regex), Drain3 templates, Egress Gate, Canary scanner, SQLite WAL outbox, Proof panel. |
| **Person 2** | SaaS & Reliability Architect | Tier 2 ingest, Tenant isolation (RLS), Multi-region cells, Idempotency, Zero loss/dup delivery, Latency proofs. |
| **Person 3** | Product, AIOps & Demo Lead | Mathematical baselines, robust z-scores, NetworkX topology correlation, root-cause ranking, Evidence Cards, safe remediation. |

---

## 24-Hour Feasibility Plan & Milestone Breakdown

| Owner | Owner Area | Hours 0 to 4 (Setup & Schemas) | Hours 4 to 12 (Core Logic) | Hours 12 to 18 (Integration & UI) | Hours 18 to 24 (Validation & Rehearsal) |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Person 1** | **Collector & Privacy** | Wire schema (`payload.schema.json`) & policy schema freeze, stream adapter, simulator baseline | Input plugins (psutil, probes, syslog), Redaction engine (regex + Shannon entropy), Drain3 log templates, Egress Gate allow-list, Canary tripwire scanner, Local failed-login detector | SQLite WAL outbox with retry & backoff, Hash-chained egress ledger (`prev_hash`), Local Egress Proof Panel (HTMX/FastAPI), Scenario injector CLI (8 judge scenarios) | Planted secret leak tests, Forced outage drills, Proof panel hash verification rehearsal, Demo timing polish |
| **Person 2** | **SaaS & Reliability** | Docker Compose multi-region cells, PostgreSQL 16 + TimescaleDB init DDL, Redis Streams, Caddy mTLS edge config | FastAPI Ingest API, UUIDv7 idempotency deduplication, Postgres Row-Level Security (RLS) tenant isolation, Multi-region cell routing (`ap-south`, `eu-central`) | Health-state evaluation engine (4 states + hysteresis + stale data downgrade), Query REST API & SSE push, Collector fleet & health dashboard views | Latency histogram measurement panel (p50/p95/p99), End-to-end load tests, Sent-vs-received ID reconciliation proof panel (zero loss/duplicates) |
| **Person 3** | **AIOps & Demo** | Baseline & robust Z-score prototype on sample vectors, One-page system data-flow sketch | Streaming anomaly detector, NetworkX dependency topology graph, Union-Find incident correlation & clustering (2-min window, 2-hop radius) | Root-cause ranking engine (onset + topology + blast radius), AIOps Evidence Card generation, Recommendation rule catalog, Incident investigation UI | Safe remediation simulation state machine (propose -> approval -> dry run -> rollback), False-alarm tuning against 10-min clean stream, Slide deck (<= 8 slides) & Q&A prep |

### Scope Cut Strategy (If Time Runs Short — In Priority Order)

If unexpected hurdles or timeline pressures arise, the team executes staged scope cuts in the following strict order to protect core judging marks:

1. **Cut 1 (First to Drop) — Drop Half-Space Trees Model:**  
   *Action:* Retain seasonal EWMA median + MAD and robust Z-score for single/joint metric anomaly detection; drop River Half-Space Trees streaming model.
2. **Cut 2 — Drop Second Regional Cell (`eu-central`):**  
   *Action:* Run two seeded tenants (`t_acme`, `t_globex`) inside `ap-south` single regional deployment. Tenant isolation, Postgres RLS, and tenant-prefixed Redis streams remain 100% provable without multi-region deployment overhead.
3. **Cut 3 — Drop Live External Network Polling (SNMP / Raw Flows):**  
   *Action:* Rely purely on the synthetic telemetry stream adapter and built-in metric generator rather than configuring physical SNMP daemons or pcap taps.
4. **Strictly Protected Non-Negotiables (NEVER Cut):**  
   *Must retain:* **Egress Gate allow-list check**, **Local Egress Proof Panel with verify button**, **SQLite WAL outbox with zero loss guarantee**, and **Explainable AIOps Evidence Cards with confidence scores**. These carry over 75% of total evaluation marks.

---

## 📋 Phase 1 Deliverables

### Person 1: Collector & Privacy Lead
Full specification available in [`docs/PHASE1_SECURITY_ARCHITECTURE.md`](docs/PHASE1_SECURITY_ARCHITECTURE.md):
1. **The Exact Allow-List of Egress Fields**: Full table defining types, examples, and privacy justification.
2. **Data Partitioning Matrix**: Explicit categorization of what stays local, what is redacted, what is dropped, and what is sent.
3. **Eight Before/After Redaction Examples**: Covering API keys, passwords, JWTs, IPs, usernames, emails, hostnames, and PANs.
4. **Pseudonymization & Fingerprinting Deep Dive**: Salted HMAC-SHA256 for entities + Drain3 online template mining.
5. **Bonus Privacy-Aware Pipeline**: Three structural controls (Typed Schema, Canary Tripwire, Signed Hash-Chained Ledger).
6. **Simulated-Telemetry Plan & Scenario Injector**: Adapter architecture, fallback generator for CPU/memory/disk/bandwidth/latency/loss/syslog secrets/failed logins, and injector commands for the 8 live judge scenarios.

### Person 2: SaaS & Reliability Architect
Full specification available in [`docs/phase1-saas-reliability.md`](docs/phase1-saas-reliability.md):
1. **Who-Can-See-What RBAC Matrix**: Defined for `viewer`, `operator`, `admin`, and `auditor`.
2. **Tenant Isolation Enforcement**: PostgreSQL 16 Row-Level Security (RLS) on all tables, `SET LOCAL app.tenant`, and tenant-namespaced Redis streams.
3. **Regional Ingest & Data Residency**: Distinct regional cells (`ap-south`, `eu-central`, `us-east`), home-region enforcement, and strict boundaries on the Global Control Plane.
4. **Global Design Decisions**: UTC + source timezone, 2-minute streaming watermark, and ULID/UUIDv7 idempotent deduplication.
5. **Real-Time Target Measurement Plan**: Concrete timestamp equations and UI verification panels for 10s dashboard p95, 15s alert creation, 60s offline detection, and zero loss / zero duplicates.
6. **Bonus**: Six-line outage and reconnect plan.

### Person 3: Product, AIOps & Demo Lead
Full specification available in [`docs/phase1_aiops_and_demo.md`](docs/phase1_aiops_and_demo.md) and [`docs/phase1_one_page_summary.md`](docs/phase1_one_page_summary.md):
1. **End-to-End Data-Flow Sketch with Trust Boundary**: Clear Mermaid diagrams mapping Tier 1 customer boundaries to Tier 2 SaaS.
2. **Four Core Production Use Cases**: Detailed *Signal $\rightarrow$ Insight $\rightarrow$ Action* workflows for Infrastructure Health, Network Latency, Failed Logins, and Fleet Health.
3. **MoSCoW Feature Roadmap & MVD**: Prioritized matrix with strict 8-scenario Minimum Viable Demo definition.
4. **Judging Question Answers**: Canonical answers for Q1 (situation before observability) and Q2 (what the team now observes).
5. **Realistic 24-Hour Plan**: Hour-by-hour milestones, 4 integration checkpoints (Hours 2, 8, 14, 20), and ordered scope-cut contingencies.
6. **Bonus AIOps Architecture**: Alert-noise reduction (topological union-find), Explainable Evidence Cards with root-cause ranking, and safe remediation simulation with auto-rollback.

---

## 🚀 Verification & Quickstart

### 1. Validate Wire Schemas (Person 1 Contracts Test)
Verifies that all valid test payloads pass and leaking or malformed payloads are rejected:
```bash
python contracts/validate_contracts.py
```

### 2. Verify Tier 1 Local Collector Architecture (Person 1 Phase 2 & 3 Suite)
Executes unit tests verifying SQLite WAL outbox, hash-chained egress ledger (`prev_hash`), Shannon entropy calculation, salted HMAC pseudonymization, canary tripwire hard-blocking, Drain3 template mining, and the 8 scenario injections:
```bash
python tests/test_collector_phase2.py
python tests/test_phase3_collector.py
```

### 3. Launch Local Collector Egress Proof Panel (Person 1 Phase 3 UI)
Starts the local on-prem proof panel with interactive HTMX endpoints (Raw data tab with visible secrets, Payload tab with exact wire bytes and SHA-256 digests, Hash verification button, and live leak_blocked counter):
```bash
python collector/ui/proof_panel.py
# Access in browser at http://localhost:8088
```

### 4. Run Scenario Injector CLI (8 Live Scenarios)
Trigger judge scenarios on demand:
```bash
python injector.py inject secret       # 1. Raw log secret leak prevention
python injector.py inject outage 90s   # 2. SaaS connectivity loss & outbox drain
python injector.py inject authburst    # 3. Repeated failed logins & pseudonymous risk
python injector.py inject latency      # 4. Latency spike & packet loss surge
python injector.py inject cpu          # 5. CPU deviation from seasonal baseline
python injector.py inject cascade      # 6. Uplink failure incident cascade
python injector.py inject dup-ooo      # 7. Duplicate & out-of-order delivery
python injector.py inject remediate    # 8. Automated remediation simulation
```

### 2. Run Baseline Prototype Simulation (Person 3 AIOps)
Simulates seasonal baseline warmup, suppression of transient spikes via the **3-of-5 sustained deviation rule** ($|z| > 3.5$), and alerting on sustained anomalies:
```bash
python saas/aiops/baseline_prototype.py
```

### 3. Run Automated Unit Tests
```bash
python -m pytest -v
```

### 4. Multi-Region Cells with Docker Compose (Person 2 SaaS)
```bash
# Launch ap-south region cell (TimescaleDB, Redis, Ingest API, Caddy)
docker compose --profile saas-ap up -d

# Launch eu-central region cell
docker compose --profile saas-eu up -d

# Launch all regional cells
docker compose --profile all up -d
```
