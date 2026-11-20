# VeilOps: Secure AIOps Observability Solution
> **CICADA 2026 Hackathon** | Two-Tier Privacy-by-Construction Observability

VeilOps is a two-tier AIOps platform in which raw telemetry physically cannot leave the customer site: the local collector turns everything into a typed, signed, metadata-only contract, and the SaaS reasons over that contract alone.

---

## Repository Structure

```
edge-guard-observability/
├── contracts/                     # Frozen wire schemas and validation suites
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
│   └── PHASE1_SECURITY_ARCHITECTURE.md # Person 1 Phase 1 Security Architecture Spec
├── collector/                     # Tier 1 Local Collector (Python 3.12, asyncio)
├── saas/                          # Tier 2 SaaS Platform (FastAPI, Redis, TimescaleDB)
├── simulator/                     # Telemetry generator and scenario injector
├── deploy/                        # Docker compose environments and certificates
└── web/                           # React + Vite dashboard
```

---

## Phase 1 Deliverables (Person 1 - Collector & Privacy Lead)

The complete Phase 1 specification is available in [`docs/PHASE1_SECURITY_ARCHITECTURE.md`](docs/PHASE1_SECURITY_ARCHITECTURE.md):
1. **The Exact Allow-List of Egress Fields**: Full table defining types, examples, and privacy justification.
2. **Data Partitioning Matrix**: Explicit categorization of what stays local, what is redacted, what is dropped, and what is sent.
3. **Eight Before/After Redaction Examples**: Covering API keys, passwords, JWTs, IPs, usernames, emails, hostnames, and PANs.
4. **Pseudonymization & Fingerprinting Deep Dive**: Salted HMAC-SHA256 for entities + Drain3 online template mining.
5. **Bonus Privacy-Aware Pipeline**: Three structural controls (Typed Schema, Canary Tripwire, Signed Hash-Chained Ledger).

---

## Validating Wire Contracts

To verify that the wire contract accepts all conforming payloads and rejects malformed/leaking payloads:

```bash
python contracts/validate_contracts.py
```
