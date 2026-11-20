# VeilOps: Secure AIOps Observability Platform
## Phase 1 Security Architecture Specification

**Role**: Person 1 (Collector, Redaction & Privacy Architect)  
**Document Version**: 1.0 (Frozen for Phase 1 Integration)  
**Standard**: Privacy-by-Construction Wire Contract & Egress Boundary

---

## 1. Executive Summary & Trust Boundary

VeilOps establishes an unconditional physical and cryptographic trust boundary between the customer site (**Tier 1: Local Collector**) and the central cloud (**Tier 2: Multi-Tenant SaaS**).

```mermaid
flowchart LR
    subgraph TIER1["Tier 1: Customer Site (Local Collector - Untrusted Cloud Boundary)"]
        direction TB
        RawSrc["Telemetry Sources\n(psutil, syslog, SNMP, Probes)"] --> Pipeline["Normalization &\nDrain3 Miner"]
        Pipeline --> LocalStore["Local SQLite Store\n(Raw Logs, PCAP, Salt, 24h Purge)"]
        Pipeline --> EgressGate{"Egress Gate\n(Strict Schema + Canary Scan)"}
        CanaryCheck["Canary Tripwire &\nEntropy Scanner"] -.-> EgressGate
        SaltVault[("Local HMAC Salt\n(Never Leaves Site)")] -.-> Pipeline
    end

    subgraph TRUST_BOUNDARY["=== ZERO RAW DATA TRUST BOUNDARY ==="]
        direction TB
        WireContract["Only Signed, Typed Wire Schema\n(No Free-Text Fields, mTLS 1.3, Ed25519)"]
    end

    subgraph TIER2["Tier 2: Regional SaaS Platform (Metadata Only)"]
        direction TB
        mTLSTerm["Ingest API / Caddy Edge\n(Certificate + Signature + Schema Recheck)"]
        RedisQ["Redis Streams Queue"]
        AIOpsEng["AIOps Engine\n(Baselines, Topo Graph, Evidence Cards)"]
        mTLSTerm --> RedisQ --> AIOpsEng
    end

    EgressGate -->|Egress Stream| WireContract
    WireContract -->|Validated Hop| mTLSTerm

    classDef secure fill:#e8f5e9,stroke:#2e7d32,stroke-width:2px;
    classDef boundary fill:#ffebee,stroke:#c62828,stroke-width:2px;
    classDef saas fill:#e1f5fe,stroke:#0277bd,stroke-width:2px;
    class TIER1 secure;
    class TRUST_BOUNDARY boundary;
    class TIER2 saas;
```

---

## 2. Exact Allow-List of Egress Fields

Every payload exiting Tier 1 must strictly match `contracts/payload.schema.json` with `additionalProperties: false`.

| Field | JSON Type | Example Value | Why It Is Safe |
| :--- | :--- | :--- | :--- |
| `payload_id` | `string` (ULID) | `"01JD8Z3K7Q9X4M2V6T1B5N8R0C"` | Synthetic random timestamp identifier generated at batch time; contains zero telemetry or user data. |
| `tenant_id` | `string` (enum-pattern) | `"t_acme"` | Pre-registered tenant identifier matching collector mTLS certificate binding for tenant isolation. |
| `collector_id` | `string` (enum-pattern) | `"c_blr_dc1"` | Static identifier of the collector instance; certified via certificate subject DN. |
| `schema_v` | `integer` | `3` | Contract schema version number for forward/backward compatibility; cannot leak data. |
| `policy_v` | `integer` | `12` | Version number of the active tenant egress policy applied by the gate. |
| `event_time_utc` | `string` (ISO 8601) | `"2026-11-20T09:15:05Z"` | Window close timestamp in normalized UTC; strictly formatted numeric string. |
| `source_tz` | `string` (IANA enum) | `"Asia/Kolkata"` | Standard IANA timezone string enabling browser dashboard local time rendering. |
| `seq` | `integer` (>= 0) | `88412` | Contiguous monotonic sequence counter per collector; used for zero-loss & gap detection. |
| `prev_hash` | `string` (64 hex SHA-256) | `"b7c1048b6245...e90a"` | SHA-256 digest of previous payload; forms tamper-evident hash-chained ledger. |
| `metrics[].src` | `string` (HMAC pseudonym) | `"h_4af29c"` | Irreversible HMAC-SHA256 pseudonym of the host/device calculated using local salt. |
| `metrics[].name` | `string` (enum) | `"cpu_pct"` | Fixed enumeration of approved metric names (`cpu_pct`, `mem_pct`, `latency_ms`, etc.). |
| `metrics[].win_s` | `integer` | `5` | Window width in seconds (`5`, `10`, `60`); strictly bounded integer. |
| `metrics[].mean` | `number` (float) | `91.2` | Aggregated window arithmetic mean; purely quantitative calculation. |
| `metrics[].p95` | `number` (float) | `97.0` | 95th percentile aggregate across raw samples in the window. |
| `metrics[].max` | `number` (float) | `99.1` | Maximum numerical sample recorded in the window. |
| `metrics[].min` | `number` (float) | `84.0` | Minimum numerical sample recorded in the window. |
| `metrics[].n` | `integer` | `5` | Sample count aggregated into this window summary. |
| `log_fingerprints[].src` | `string` (HMAC pseudonym) | `"h_4af29c"` | Irreversible host pseudonym matching the metrics source ID. |
| `log_fingerprints[].tpl` | `string` (6-16 hex) | `"9f3a1c"` | MD5/SHA256 truncated digest of the Drain3 parsed template structure; text is suppressed. |
| `log_fingerprints[].sev` | `string` (enum) | `"error"` | Normalized syslog severity enum (`debug`, `info`, `warn`, `error`, `critical`). |
| `log_fingerprints[].count` | `integer` | `412` | Frequency count of how many times this template fired during the window. |
| `security[].src` | `string` (HMAC pseudonym) | `"p_77d1"` | Irreversible pseudonym of client principal, remote IP, or attacking source. |
| `security[].cat` | `string` (enum) | `"auth_fail"` | Fixed security event category (`auth_fail`, `port_scan`, `ddos_suspect`, `rate_limit`). |
| `security[].count` | `integer` | `47` | Quantity of security occurrences within the local evaluation window. |
| `security[].win_s` | `integer` | `60` | Duration of the sliding detection window in seconds. |
| `security[].risk` | `string` (enum) | `"high"` | Categorical risk indicator enum (`low`, `medium`, `high`, `critical`). |
| `health.state` | `string` (enum) | `"fair"` | Four-state health classification (`excellent`, `good`, `fair`, `poor`). |
| `health.reason_codes` | `array[string]` (enum) | `["CPU_BASELINE_DEV"]` | Upper snake_case reason tokens explaining any downgrade; zero descriptive prose. |
| `signature` | `string` (Ed25519) | `"ed25519:v1d0mN4K7+..."` | Cryptographic signature of collector private key over serialized canonical payload bytes. |

---

## 3. Data Partitioning Matrix: Local vs. Redacted vs. Dropped vs. Sent

| Category | Stays Local (Site Vault) | Redacted / Pseudonymized | Dropped Entirely | Sent to SaaS (Wire Egress) |
| :--- | :--- | :--- | :--- | :--- |
| **System Logs** | Raw log text, stack traces, parameters (24h retention, local SQLite). | Mined by Drain3 into static pattern; parameters extracted. | Variable parameters, unparseable raw message strings. | Truncated template hash (`tpl: "9f3a1c"`), severity enum, count. |
| **Host & Device IDs** | Real hostnames, FQDNs, internal MAC addresses, local asset tags. | Salted HMAC-SHA256 (`HMAC(host, salt)`). | Unsalted prefixes, domain names, OS version strings. | Truncated host pseudonym (`src: "h_4af29c"`). |
| **User & Client Identity** | Usernames, employee IDs, customer accounts, raw IP addresses. | Salted HMAC-SHA256 (`HMAC(ip_or_user, salt)`). | Cleartext identities, emails, authentication headers. | Entity pseudonym (`src: "p_77d1"`). |
| **Authentication & Access** | Full login failure logs, SSH debug streams, Kerberos/PAM tokens. | Transformed into failure frequency & window duration. | Passwords, hashes, salt values, cookie headers, API keys. | Security indicator: `cat: "auth_fail"`, `count: 47`, `win_s: 60`, `risk: "high"`. |
| **Network & Flows** | Raw packet captures, PCAP files, payload bytes, raw socket buffers. | Round-trip times and packet loss counts averaged. | Packet payload bytes, DNS queries, HTTP URI parameters. | Quantitative aggregates: `latency_ms` mean/p95, `packet_loss_pct`. |
| **Collector State** | Local SQLite WAL outbox, private Ed25519 key, salt configuration. | Self-monitoring metrics computed over 10s intervals. | Local database connection strings, file paths. | Contiguous `seq`, `prev_hash`, health state & standardized reason code enum. |

---

## 4. Eight Before/After Redaction Examples

The local pipeline sanitizes and scrubs raw data before any serialization occurs.

| # | Telemetry Type | Raw Input (Collector Local Store Only) | Redacted / Sanitized State | Wire Contract Egress Value | Detection / Scrubbing Mechanism |
| :- | :--- | :--- | :--- | :--- | :--- |
| **1** | **API Key** | `Authorization: Bearer sk-live-51NzT42eXy8K9w01MnpQrStUvWxYz` | `Authorization: Bearer [REDACTED_API_KEY]` | *Field dropped entirely; auth failure counted if rejected.* | Regex `sk-(?:live\|test)-[0-9a-zA-Z]{24,}` + Shannon entropy > 4.2. |
| **2** | **Password** | `POST /login HTTP/1.1 user=admin&password=SuperSecretPassword123!` | `POST /login HTTP/1.1 user=[REDACTED]&password=[REDACTED]` | `{"cat": "auth_fail", "count": 1, "win_s": 60, "risk": "low"}` | Form regex `(?i)(password\|passwd\|pwd)=([^&\s]+)` + drop from wire contract. |
| **3** | **JWT Token** | `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIx...` | `Bearer [REDACTED_JWT]` | *Field dropped; no token or payload string permitted in schema.* | Regex `eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`. |
| **4** | **IP Address** | `Failed SSH login from 192.168.1.105 on port 22` | `Failed SSH login from p_77d1 on port 22` | `{"src": "p_77d1", "cat": "auth_fail", "count": 1}` | IPv4/IPv6 pattern matching + `HMAC-SHA256("192.168.1.105", salt)[:6]`. |
| **5** | **Username** | `PAM-auth failure for user 'sagar.sharma' on tty1` | `PAM-auth failure for user 'p_3b8a' on tty1` | `{"src": "p_3b8a", "cat": "auth_fail", "count": 1}` | PAM parser regex `user\s+'([^']+)'` + salted HMAC pseudonymization. |
| **6** | **Email** | `Alert dispatched to ops-admin@datacenter.acme.corp` | `Alert dispatched to [REDACTED_EMAIL]` | *Field suppressed entirely by Egress Gate.* | RFC 5322 regex `[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+`. |
| **7** | **Hostname** | `Disk full on prd-db-master-01.internal.corp` | `Disk full on h_4af29c` | `{"src": "h_4af29c", "name": "disk_pct", "mean": 99.4}` | Hostname regex `[a-zA-Z0-9-]+(?:\.[a-zA-Z0-9-]+)*` + salted host HMAC. |
| **8** | **Card / PAN** | `Transaction error for PAN 4532-8901-2345-6789` | `Transaction error for PAN [REDACTED_PAN]` | *Field suppressed; Drain3 mines template without numbers.* | 13-19 digit card regex + Luhn checksum validation. |

---

## 5. Pseudonymization and Log Template Fingerprinting

### A. Non-Reversible Source Pseudonymization
To maintain topological graph correlation across metrics, logs, and security events without exposing infrastructure topology or customer IP addresses:
1. **Local Secret Salt**: Upon initial collector bootstrap, a high-entropy 256-bit cryptographically secure random salt is generated and written to local disk (mode `0600`):
   $$\text{Salt} \leftarrow \text{CSPRG}(256\text{ bits})$$
   *The salt never leaves the customer environment under any condition.*
2. **Deterministic Pseudonym Function**:
   $$\text{Pseudonym}(\text{ID}, \text{prefix}) = \text{prefix} \parallel \text{Hex}(\text{HMAC-SHA256}(\text{Salt}, \text{ID}))[0:6]$$
   - Host entities receive prefix `h_` (e.g. `prd-db-01` $\rightarrow$ `h_4af29c`).
   - Principals and IPs receive prefix `p_` (e.g. `192.168.1.105` $\rightarrow$ `p_77d1`).
3. **Security Properties**:
   - **Deterministic**: Metrics and logs from the same source correlate identically within the customer's tenant dashboard.
   - **Non-Reversible**: A compromise of the SaaS database yields zero hostnames or IP addresses; rainbow tables cannot be constructed without the tenant's on-premise salt.

### B. Drain3 Online Log Template Fingerprinting
Rather than streaming log text off-site, VeilOps mines log structural patterns locally in real time:
1. **Online Parse Tree**: Log lines pass into an active Drain3 parse tree which distinguishes constant tokens from variable values (such as timestamps, GUIDs, memory addresses, and file paths) and substitutes wildcards `<*>`.
   - *Raw log*: `Connection lost to 10.0.1.45 after 3 retries, timeout=30s`
   - *Parsed template*: `Connection lost to <*> after <*> retries, timeout=<*>`
2. **Template Digest Generation**:
   $$\text{TemplateHash} = \text{Hex}(\text{MD5}(\text{TemplateStructure}))[0:6]$$
   The template text is converted into a 6-character hex token (e.g. `9f3a1c`).
3. **Aggregation Window**:
   During each 5-second aggregation window, the collector counts template occurrences. The egress gate transmits strictly:
   ```json
   {"src": "h_4af29c", "tpl": "9f3a1c", "sev": "error", "count": 412}
   ```
   *The cloud never sees or stores a single byte of log text.*

---

## 6. Bonus: Privacy-Aware Pipeline (Three Structural Controls)

1. **Typed Egress Schema (`additionalProperties: false`)**:  
   The wire schema mathematically forbids all free-text fields (`message`, `log`, `body`) and rejects any unexpected property, ensuring secrets have no data field in which to hide.

2. **Canary Tripwire & Entropy Gate**:  
   Every serialized byte buffer is scanned prior to network transmission against planted canary honey-tokens, common credential signatures, and Shannon-entropy thresholds, instantly blocking egress and sounding a local alarm if a leak is attempted.

3. **Signed Hash-Chained Egress Ledger**:  
   Every outbound payload is signed with the collector's Ed25519 private key and cryptographically bound to its predecessor via `prev_hash` in an immutable local ledger, allowing operators and auditors to mathematically prove that cloud-stored metadata matches the local egress record byte-for-byte.

---

## 7. Integration & Team Handoff (Phase 1 Checkpoint)

| Component | Owner | Deliverable Status (Hour 0 to 4) | Next Milestone |
| :--- | :--- | :--- | :--- |
| **Tier 1 (Collector & Privacy)** | **Person 1** | Wire schema frozen in `contracts/payload.schema.json`; sample payloads (valid & invalid) created; validation script verified. | Build collector input plugins, Drain3 miner, and Egress Gate (Hours 4–12). |
| **Tier 2 (SaaS & Reliability)** | **Person 2** | Ready to consume `payload.schema.json` into Ingest API, PostgreSQL + TimescaleDB RLS schema, and Redis Streams. | Implement Ingest API, idempotency, and RLS tenant separation (Hours 4–12). |
| **Tier 3 (AIOps & Demo)** | **Person 3** | Sample payloads provide baseline schemas for baselines, topology graphs, and incident evidence cards. | Implement anomaly detection, topology graph, and incident grouping (Hours 4–12). |
