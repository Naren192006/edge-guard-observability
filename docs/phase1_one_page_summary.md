# VeilOps: Phase 1 — One-Page System & Architecture Summary

**Evaluation Checklist:** Phase 1 (All 5 Criteria) | **Lead:** Person 3 | **Contributors:** Person 1 & Person 2

---

## 1. System Data-Flow & Trust Boundary

```mermaid
flowchart LR
    subgraph TIER1["Tier 1: Customer Site (Collector)"]
        A["Telemetry Sources\n(Host, Net, Syslog, Sim)"] --> B["Normalize & Redact\n(HMAC Salt, Regex, Entropy)"]
        B --> C["Aggregate & Fingerprint\n(5s Windows, Drain3)"]
        C --> D["Egress Gate & Outbox\n(Schema Allow-list, Ed25519)"]
    end

    D ===|"TRUST BOUNDARY (mTLS 1.3, Metadata Only, No Free Text)"| E["Ingest Edge (Caddy mTLS)"]

    subgraph TIER2["Tier 2: SaaS Platform (Central)"]
        E --> F["FastAPI Ingest\n(Sig & Schema Check)"]
        F --> G["Redis Streams\n(Tenant-Keyed)"]
        G --> H["TimescaleDB\n(RLS per Tenant)"]
        G --> I["AIOps Engine\n(Baselines, Graph, Evidence)"]
        H --> J["React Dashboard\n(SSE Push)"]
        I --> J
    end
```

---

## 2. Why Raw Telemetry Must Stay in the Customer Environment and Why the SaaS Receives Metadata Only

- **Data Exposure and Larger Attack Surface:** Forwarding raw logs and system traces creates an immense central attack honeypot; compromising the multi-tenant SaaS exposes all tenants' infrastructure, architecture, and private operations at once.
- **Compliance and Data Residency:** Raw logs invariably capture PII, banking records, and health data, triggering immediate compliance breaches under GDPR (cross-border transfers), HIPAA, PCI-DSS, and national data-sovereignty mandates when shipped off-premises.
- **Secrets in Logs:** Software routinely leaks unredacted API tokens, credentials, private certificates, and passwords into logs; regex scrubbing alone is inherently leaky, making a strictly typed schema with zero free-text fields the only mathematically safe guarantee.
- **Customer Trust and Local Control:** Regulated enterprises require complete, verifiable ownership of their operational data; storing raw records locally under 24-hour purge policies preserves customer sovereignty while an immutable hash-chained ledger provides verifiable proof of zero leak.

*What the SaaS can still do with metadata alone:*  
With metadata alone (5-second statistical rollups, Drain3 template hashes, pseudonymous IDs, and risk scores), the SaaS can fully detect complex multi-metric anomalies, correlate alerts across 2-hop topology graphs, rank root causes with mathematical confidence, and suggest actionable remediations without ever seeing a single byte of sensitive raw data.

---

## 3. Allow-Listed Fields Transmitted Across Trust Boundary

| Field Name | Type | Example Value | Why It Is Safe |
| :--- | :--- | :--- | :--- |
| `payload_id` | `string` (UUIDv7/ULID) | `"01JD8Z3K7Q9X4M2V6T1B5N8R0C"` | Ephemeral unique identifier; contains timestamp and entropy only. |
| `tenant_id` | `string` (Identifier) | `"t_acme"` | Bounded tenant token matching TLS certificate claim. |
| `collector_id` | `string` (Identifier) | `"c_blr_dc1"` | Registered identifier of the forwarding collector. |
| `schema_v` / `policy_v` | `integer` | `3` / `12` | Monotonic version numbers for contract enforcement. |
| `event_time_utc` | `string` (ISO 8601) | `"2026-11-20T09:15:05Z"` | Standard UTC timestamp for window alignment. |
| `source_tz` | `string` (IANA Tz) | `"Asia/Kolkata"` | Timezone name for localized operator rendering. |
| `seq` | `integer` | `88412` | Contiguous counter for gap and duplicate detection. |
| `prev_hash` | `string` (Hex SHA-256) | `"b7c1...e90a"` | Cryptographic link ensuring hash-chained ledger integrity. |
| `metrics[].src` | `string` (Pseudonym) | `"h_4af29c"` | Salted HMAC pseudonym of the originating host/device. |
| `metrics[].name` | `string` (Enum) | `"cpu_pct"`, `"latency_ms"` | Strict allow-list enum of approved metric names. |
| `metrics[].win_s` | `integer` | `5` | Window aggregation duration in seconds. |
| `metrics[].mean/p95/max` | `number` (Float) | `91.2`, `97.0`, `99.1` | Pure numeric statistical rollups; zero text content. |
| `log_fingerprints[].tpl` | `string` (Hex Hash) | `"9f3a1c"` | MD5/SHA-256 hash of Drain3 mined template; text stays local. |
| `log_fingerprints[].sev` | `string` (Enum) | `"error"`, `"warning"` | Bounded log severity classification enum. |
| `log_fingerprints[].count`| `integer` | `412` | Frequency count within aggregation window. |
| `security[].cat` | `string` (Enum) | `"auth_fail"` | Security event category enum. |
| `security[].risk` | `string` (Enum) | `"high"`, `"medium"`, `"low"` | Calculated risk rating based on sliding failure velocity. |
| `health.state` | `string` (Enum) | `"fair"`, `"poor"` | Deterministic status enum (Excellent/Good/Fair/Poor). |
| `signature` | `string` (Ed25519) | `"ed25519:6a3f..."` | Cryptographic signature over serialized bytes. |

---

## 4. Eight Before/After Redaction & Transformation Examples

| Category | Raw Data (Collector Local Store Only) | Sanitized Output Crossing Trust Boundary | Transformation Mechanism |
| :--- | :--- | :--- | :--- |
| **1. API Key** | `Authorization: Bearer sk_live_98a7f6e5d4c3b2a1` | *Field dropped; Canary hit raises local alarm* | Regex scrub + entropy check; omitted from wire contract |
| **2. Password** | `password=SuperSecretPass!123` | *Field completely stripped* | Regex credential scanner wipes sensitive parameter |
| **3. JWT** | `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWI...` | *Omitted from metadata payload* | High-entropy base64 filter; never serialized to egress |
| **4. IP Address** | `192.168.1.145` | `"src": "h_4af29c"` | HMAC-SHA256(`ip`, `site_salt`)[:8] pseudonym |
| **5. Username** | `admin_db_root` | `"src": "u_9b821a"` | HMAC-SHA256(`user`, `site_salt`)[:8] pseudonym |
| **6. Email** | `devops-lead@acme-corp.internal` | `"src": "e_31f4dc"` | Salted HMAC pseudonym; raw email purged |
| **7. Hostname** | `prod-db-master-01.internal.net` | `"src": "h_77d12f"` | Host identity mapped to stable site-specific pseudonym |
| **8. Card-like** | `4532-1189-9023-4412` | *Rejected and scrubbed* | Luhn algorithm & credit card regex filter |

---

## 5. Simulated Telemetry Plan & Scenario Injector CLI

* **Baseline Stream Adapter:** Generates realistic sinusoidal daily curves for `cpu_pct`, `memory_pct`, `latency_ms`, and `packet_loss_pct` with configurable Gaussian noise. Ingests simulated syslog streams with injected canary strings.
* **Scenario Injector CLI Commands:**
  1. `inject secret`: Plants canary API keys into syslog stream; verifies Egress Gate blocks leak.
  2. `inject outage 90s`: Simulates network barrier; validates outbox queuing and post-reconnect zero loss/zero duplicate recovery.
  3. `inject authburst`: Triggers 50 rapid login failures; verifies pseudonymous risk alert emission.
  4. `inject latency`: Injects network latency and packet loss degradation on edge uplink.
  5. `inject cpu`: Pushes CPU to $95\%$ outside seasonal baseline; validates robust z-score trigger.
  6. `inject cascade`: Simulates switch failure causing 9 alerts; validates single incident correlation.
  7. `inject dup-ooo`: Sends replayed and out-of-order payloads; verifies idempotent deduplication.
  8. `inject remediate`: Triggers incident with recommended action for simulation workflow.

---

## 6. Team Roles & Ownership Matrix

| Member | Primary Role | Core Modules Owned |
| :--- | :--- | :--- |
| **Person 1** | Collector & Privacy Lead | `collector/` (inputs, redaction, Drain3, Egress Gate, SQLite outbox, Proof Panel), `simulator/` |
| **Person 2** | SaaS & Reliability Lead | `saas/ingest/`, `saas/api/`, `saas/db/`, `deploy/` (Caddy mTLS, TimescaleDB, RLS, SSE, Health Engine) |
| **Person 3** | Product, AIOps & Demo Lead | `saas/aiops/` (baselines, z-score, topology graph, cause ranking, evidence cards, remediation), Presentation |

---

## 7. Official Answers to Phase 1 Sheet Questions

* **Q1: What was the situation before observability?**  
  Each site relied on separate tools and manual log searching (`grep`), static thresholds produced noisy duplicate alerts, and the only central view required shipping raw logs off site, which exposed secrets and raised compliance risk.
* **Q2: What does the team now observe with the solution?**  
  Fleet and collector health in four states, latency and packet loss, resource trends against baselines, failed-login risk, anomalies grouped into incidents with likely causes, and a ledger of exactly what left each site.
