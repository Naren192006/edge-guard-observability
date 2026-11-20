# VeilOps: Secure AIOps Observability Solution

> **CICADA 2026 Hackathon** | **Two-Tier Privacy-by-Construction Observability & Explainable AIOps**

VeilOps is a two-tier AIOps observability platform in which raw telemetry physically cannot leave the customer site: the local collector turns everything into a typed, signed, metadata-only contract, and the SaaS reasons over that contract alone.

---

## 🗂️ Repository Architecture

```text
edge-guard-observability/
├── contracts/                         # Frozen wire schemas and validation suites
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
├── collector/                         # Tier 1 Local Collector (Python 3.12, asyncio)
│   ├── inputs/                        # Telemetry plugins (psutil, ping/TCP, syslog, flow)
│   ├── normalize.py                   # UTC & source timezone normalization
│   ├── redact.py                      # Shannon entropy, regex rules, salted HMAC pseudonyms
│   ├── aggregate.py                   # 5-second window statistical aggregation
│   ├── fingerprint.py                 # Drain3 online log template mining
│   ├── egress_gate.py                 # Cryptographic schema validation & canary tripwire
│   ├── outbox.py                      # SQLite WAL outbox with hash-chained ledger
│   └── ui/                            # FastAPI + HTMX Egress Proof Panel
├── saas/                              # Tier 2 SaaS Platform (FastAPI, Redis Streams, TimescaleDB)
│   ├── ingest/                        # FastAPI mTLS ingest, Ed25519 verification, deduplication
│   ├── aiops/                         # AIOps Engine: Baselines, graph topology, cause ranking
│   │   ├── __init__.py
│   │   └── baseline_prototype.py      # Phase 1 prototype: EWMA median/MAD + robust z-score
│   ├── workers/                       # Redis Streams consumers & TimescaleDB writers
│   ├── api/                           # REST Query API & Server-Sent Events (SSE)
│   └── db/migrations/                 # TimescaleDB hypertables & PostgreSQL RLS policies
├── web/                               # React + Vite + Tailwind + ECharts Dashboard
├── simulator/                         # Telemetry stream generator & 8-scenario injector CLI
├── deploy/                            # Docker compose environments and certificates
├── docs/                              # Architectural specs and judging deliverables
│   ├── PHASE1_SECURITY_ARCHITECTURE.md # Person 1: Security & Privacy Architecture Spec
│   ├── phase1_aiops_and_demo.md        # Person 3: Master Product, AIOps & Demo Spec
│   └── phase1_one_page_summary.md      # Person 3: One-page system & allow-list summary
└── tests/                             # Automated test suite
    └── test_baseline_prototype.py      # Unit tests for AIOps baseline prototype
```

---

## 👥 Team Ownership & Evaluation Split

| Member | Focus Area | Core Responsibilities |
| :--- | :--- | :--- |
| **Person 1** | Collector & Privacy Lead | Inputs, regex/entropy redaction, Drain3 template mining, Egress Gate, SQLite WAL outbox, Proof Panel, Canary tripwire. |
| **Person 2** | SaaS & Reliability Lead | Caddy mTLS, FastAPI Ingest API, TimescaleDB RLS, Redis Streams, health-state engine, fleet UI, latency & replay metrics. |
| **Person 3** | Product, AIOps & Demo Lead | Mathematical baselines, robust z-scores, NetworkX topology correlation, root-cause ranking, Evidence Cards, safe remediation. |

---

## 🚀 Phase 1 Quickstart & Validation

### 1. Validate Wire Schemas (Person 1 Contracts Test)
Verifies that all valid test payloads pass and leaking or malformed payloads are rejected:
```bash
python contracts/validate_contracts.py
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

---

## 📖 Phase 1 Documentation Links

- **[Security Architecture Spec (Person 1)](file:///docs/PHASE1_SECURITY_ARCHITECTURE.md):** Exact allow-list of egress fields, data partitioning matrix, 8 before/after redaction examples, HMAC pseudonymization, and privacy controls.
- **[Master Product & AIOps Spec (Person 3)](file:///docs/phase1_aiops_and_demo.md):** End-to-end data-flow sketch with trust boundary, four core use cases, MoSCoW roadmap, 24-hour team plan, and bonus capabilities.
- **[One-Page System & Allow-List Summary (Person 3)](file:///docs/phase1_one_page_summary.md):** Concise one-page sketch, allow-list table, 8 redaction examples, and official answers to Phase 1 judging questions (Q1 and Q2).
- **[Strict Wire Schema Contract](file:///contracts/payload.schema.json):** The canonical wire schema with `additionalProperties: false` and zero free-text strings.
