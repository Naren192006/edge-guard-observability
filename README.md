# VeilOps: Secure AIOps Observability Solution
> **CICADA 2026 Hackathon** | Two-Tier Privacy-by-Construction Observability

VeilOps is a two-tier AIOps platform in which raw telemetry physically cannot leave the customer site: the local collector turns everything into a typed, signed, metadata-only contract, and the SaaS reasons over that contract alone.

---

## Repository Structure & Ownership

```
edge-guard-observability/
├── contracts/                     # Frozen wire schemas and validation suites [Shared / Person 1]
│   ├── payload.schema.json        # Strict JSON Schema (additionalProperties: false)
│   ├── policy.schema.json         # Tenant data policy schema
│   ├── sample_policy.yaml         # Example tenant egress policy
│   ├── validate_contracts.py      # Automated contract validation test
│   └── samples/                   # Conformance test vectors
│       ├── valid_payload_1.json   # Normal steady-state telemetry
│       ├── valid_payload_2.json   # High CPU & auth failure burst
│       ├── valid_payload_3.json   # Latency spike & error fingerprints
│       ├── rejected_payload_1_free_text.json    # Rejection: contains forbidden "message"
│       ├── rejected_payload_2_unknown_field.json # Rejection: contains unlisted "raw_ip"
│       └── rejected_payload_3_invalid_enum.json # Rejection: unapproved enum values
├── docs/                          # Architectural and phase documentation
│   ├── PHASE1_SECURITY_ARCHITECTURE.md # Person 1: Collector & Privacy Architecture Spec
│   └── phase1-saas-reliability.md      # Person 2: SaaS & Reliability Architecture Spec
├── collector/                     # Tier 1 Local Collector [Person 1: Collector & Privacy]
│   ├── inputs/                    # Metrics, Probes, Syslog, Stream Adapter
│   ├── normalize.py               # UTC + source timezone mapping
│   ├── redact.py                  # Entropy scan, Regex scrubbing, HMAC pseudonyms
│   ├── aggregate.py               # 5-second tumbling windows
│   ├── fingerprint.py             # Drain3 template mining
│   ├── egress_gate.py             # Allow-list validation, Canary scan, Ed25519 signing
│   ├── outbox.py                  # SQLite WAL outbox, hash-chained ledger
│   └── ui/                        # HTMX / FastAPI Egress Proof Panel (Local)
├── saas/                          # Tier 2 SaaS Platform [Person 2: SaaS & Reliability]
│   ├── ingest/                    # FastAPI Regional Ingest API & Idempotency
│   ├── workers/                   # TimescaleDB writer, Stream consumers
│   ├── db/
│   │   ├── init.sql               # Postgres 16 + TimescaleDB DDL + Row-Level Security
│   │   └── migrations/
│   ├── api/                       # REST + SSE Query API for dashboards
│   └── tests/                     # SaaS Ingest & RLS test suite
├── saas/aiops/                    # AIOps Reasoning Engine [Person 3: AIOps & Demo]
│   ├── baselines.py               # Seasonal EWMA/MAD, Robust Z-Score, Half-Space Trees
│   ├── correlate.py               # Topology graph (NetworkX) + Union-Find incident merging
│   ├── rank.py                    # Cause ranking (earliest onset, topology, blast radius)
│   └── recommendations.py         # Rule library & Evidence-Card generators
├── simulator/                     # Telemetry generator and scenario injector [Person 1 & 3]
│   ├── stream_adapter.py          # Simulated stream provider
│   └── scenario_injector.py       # Injects 8 judge scenarios
├── deploy/                        # Docker compose environments and certificates [Person 2]
│   ├── docker-compose.yml         # Multi-cell setup (ap-south, eu-central)
│   ├── caddy/                     # mTLS terminator configuration
│   └── certs/                     # Collector & Server mTLS certificates
└── web/                           # React + Vite dashboard [Person 3 & Person 2]
```

---

## 3-Person Team Split & Responsibilities

| Owner | Focus Area | Key Deliverables |
| :--- | :--- | :--- |
| **Person 1** | Collector & Privacy Lead | Tier 1 collector, Redaction, Drain3 templates, Egress Gate, Canary scanner, SQLite outbox, Proof panel |
| **Person 2** | SaaS & Reliability Architect | Tier 2 ingest, Tenant isolation (RLS), Multi-region cells, Idempotency, Zero loss/dup delivery, Latency proofs |
| **Person 3** | AIOps & Demo Lead | Anomaly detection, Incident correlation, Cause ranking, Evidence cards, React incident views, Demo story |

---

## Phase 1 Deliverables

### Person 1: Collector & Privacy Lead
Full specification available in [`docs/PHASE1_SECURITY_ARCHITECTURE.md`](docs/PHASE1_SECURITY_ARCHITECTURE.md):
1. **The Exact Allow-List of Egress Fields**: Full table defining types, examples, and privacy justification.
2. **Data Partitioning Matrix**: Explicit categorization of what stays local, what is redacted, what is dropped, and what is sent.
3. **Eight Before/After Redaction Examples**: Covering API keys, passwords, JWTs, IPs, usernames, emails, hostnames, and PANs.
4. **Pseudonymization & Fingerprinting Deep Dive**: Salted HMAC-SHA256 for entities + Drain3 online template mining.
5. **Bonus Privacy-Aware Pipeline**: Three structural controls (Typed Schema, Canary Tripwire, Signed Hash-Chained Ledger).

### Person 2: SaaS & Reliability Architect
Full specification available in [`docs/phase1-saas-reliability.md`](docs/phase1-saas-reliability.md):
1. **Who-Can-See-What RBAC Matrix**: Defined for `viewer`, `operator`, `admin`, and `auditor`.
2. **Tenant Isolation Enforcement**: PostgreSQL 16 Row-Level Security (RLS) on all tables, `SET LOCAL app.tenant`, and tenant-namespaced Redis streams.
3. **Regional Ingest & Data Residency**: Distinct regional cells (`ap-south`, `eu-central`, `us-east`), home-region enforcement, and strict boundaries on the Global Control Plane.
4. **Global Design Decisions**: UTC + source timezone, 2-minute streaming watermark, and ULID/UUIDv7 idempotent deduplication.
5. **Real-Time Target Measurement Plan**: Concrete timestamp equations and UI verification panels for 10s dashboard p95, 15s alert creation, 60s offline detection, and zero loss / zero duplicates.
6. **Bonus**: Six-line outage and reconnect plan.

---

## Verification & Quickstart

### 1. Validating Wire Contracts
To verify that the wire contract accepts all conforming payloads and rejects malformed/leaking payloads:
```bash
python contracts/validate_contracts.py
```

### 2. Multi-Region Cells with Docker Compose
```bash
# Launch ap-south region cell (TimescaleDB, Redis, Ingest API, Caddy)
docker compose --profile saas-ap up -d

# Launch eu-central region cell
docker compose --profile saas-eu up -d

# Launch all regional cells
docker compose --profile all up -d
```
