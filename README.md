# VeilOps: Secure AIOps Observability Platform

> **CICADA 2026 Hackathon** | **Privacy by Construction Telemetry & Explainable AIOps**

VeilOps is a two-tier AIOps observability solution where raw telemetry physically cannot leave the customer premises. The local collector normalizes, scrubs, aggregates, and transforms telemetry into a signed, metadata-only contract that contains **zero free-text fields**. The SaaS tier consumes this contract to deliver baseline anomaly detection, topology-aware root-cause analysis, and explainable evidence cards.

---

## 🗂️ Repository Architecture

```text
edge-guard-observability/
├── contracts/                  # Frozen wire schemas, policy schemas, sample payloads
│   └── sample_payload.json     # Valid wire contract sample (JSON Schema compliant)
├── collector/                  # Tier 1: Local Collector (Python 3.12, asyncio)
│   ├── inputs/                 # Telemetry plugins (psutil, ping/TCP, syslog, flow)
│   ├── normalize.py            # UTC & source timezone normalization
│   ├── redact.py               # Shannon entropy, regex rules, salted HMAC pseudonyms
│   ├── aggregate.py            # 5-second window statistical aggregation
│   ├── fingerprint.py          # Drain3 online log template mining
│   ├── egress_gate.py          # Cryptographic schema validation & canary tripwire
│   ├── outbox.py               # SQLite WAL outbox with hash-chained ledger
│   └── ui/                     # FastAPI + HTMX Egress Proof Panel
├── saas/                       # Tier 2: Central Multi-Tenant SaaS
│   ├── ingest/                 # FastAPI mTLS ingest, Ed25519 verification, deduplication
│   ├── aiops/                  # AIOps Engine: Baselines, graph topology, cause ranking
│   │   ├── __init__.py
│   │   └── baseline_prototype.py  # Phase 1 prototype: EWMA median/MAD + robust z-score
│   ├── workers/                # Redis Streams consumers & TimescaleDB writers
│   ├── api/                    # REST Query API & Server-Sent Events (SSE)
│   └── db/migrations/          # TimescaleDB hypertables & PostgreSQL RLS policies
├── web/                        # React + Vite + Tailwind + ECharts Dashboard
├── simulator/                  # Telemetry stream generator & 8-scenario injector CLI
├── deploy/                     # Docker Compose profiles (ap-south, eu-central), Caddy mTLS certs
├── docs/                       # Architectural specs and judging deliverables
│   ├── phase1_aiops_and_demo.md     # Detailed Phase 1 submission document
│   └── phase1_one_page_summary.md   # One-page executive summary & data-flow sketch
└── tests/                      # Pytest automated test suite
    └── test_baseline_prototype.py   # Unit tests for baseline prototype
```

---

## 👥 Team Ownership & Evaluation Split

| Member | Focus Area | Core Responsibilities |
| :--- | :--- | :--- |
| **Person 1** | Collector & Privacy | Inputs, regex/entropy redaction, Drain3 template mining, Egress Gate, SQLite WAL outbox, Proof Panel, Canary tripwire. |
| **Person 2** | SaaS & Reliability | Caddy mTLS, FastAPI Ingest API, TimescaleDB RLS, Redis Streams, health-state engine, fleet UI, latency & replay metrics. |
| **Person 3** | Product & AIOps Lead | Mathematical baselines, robust z-scores, NetworkX topology correlation, root-cause ranking, Evidence Cards, safe remediation. |

---

## 🚀 Phase 1: Prototype Quickstart

### 1. Run Baseline Prototype Simulation
```bash
python saas/aiops/baseline_prototype.py
```
*Demonstrates:*
- Seasonal baseline warmup (hour-of-week profile).
- Transient spike suppression via the **3-of-5 sustained deviation rule** ($|z| > 3.5$).
- Confirmed alert generation when anomaly is sustained across evaluation windows.

### 2. Execute Automated Unit Tests
```bash
python -m pytest -v
```

---

## 📖 Phase 1 Documentation Links

- **[Phase 1 Master Product & AIOps Spec](file:///docs/phase1_aiops_and_demo.md):** Complete data-flow architecture, four core use cases, MoSCoW feature roadmap, 24-hour plan, and bonus capabilities.
- **[One-Page System & Allow-List Summary](file:///docs/phase1_one_page_summary.md):** Concise one-page sketch, allow-list table, 8 before/after redaction examples, role split, and judging question answers.
- **[Sample Wire Contract Payload](file:///contracts/sample_payload.json):** Valid JSON payload conforming to the strict wire contract (`additionalProperties: false`, no free text).
