# VeilOps Phase 4: Final Privacy Demo, Validation & Presentation Guide
## Person 1 (Collector, Redaction & Privacy Architect)

**Scope**: Final Validation & Presentation (30 Marks)  
**Status**: Ready for Live Demonstration & Judging Q&A

---

## 1. Demo Runbooks for Person 1 Scenarios

### Scenario 1: Raw Log Contains a Planted Secret
* **Objective**: Prove that even when raw logs contain API keys, passwords, or tokens, they are physically stripped before egress. Zero sensitive bytes reach SaaS.
* **Exact Command**:
  ```bash
  python injector.py inject secret
  ```
* **Step-by-Step Screen Walkthrough**:
  1. **Collector Raw Tab (`http://localhost:8088`)**:
     - Click **"🔍 Raw Data Tab (On-Prem Secrets Visible)"**.
     - Point out raw syslog entry containing `CANARY_AKIA_IOSFODNN7EXAMPLE` and `password=SuperSecretPassword123!`.
     - Highlight: *"This raw text resides solely in the collector's encrypted SQLite store on-premise (24h rolling purge)."*
  2. **Egress Proof Panel (`http://localhost:8088`)**:
     - Switch to **"📦 Egress Wire Payloads"**.
     - Expand the latest ledger row.
     - Show `log_fingerprints`:
       ```json
       {"src": "h_4af29c", "tpl": "e7fe13", "sev": "error", "count": 1}
       ```
     - Point out: `CANARY_AKIA` and `SuperSecretPassword123!` are completely absent.
     - The canary tripwire scanner shows **0 hits** on outbound bytes because Drain3 mined the structural template before serialization.
  3. **SaaS Dashboard / Ingest API**:
     - Show the ingested record in SaaS. The cloud only receives the 6-character hex hash (`e7fe13`) and occurrence count (`1`). Zero text exists in cloud memory or database.

---

### Scenario 3: Repeated Failed Logins (Auth-Burst)
* **Objective**: Demonstrate that brute-force attempts are detected locally; only aggregated risk indicators and pseudonyms leave the site.
* **Exact Command**:
  ```bash
  python injector.py inject authburst
  ```
* **Step-by-Step Screen Walkthrough**:
  1. **Collector Processing**:
     - The local sliding-window detector tracks 55 failed PAM/SSH login events within 30 seconds.
     - The attacker entity `192.168.1.105` is hashed using the customer's on-prem salt to `p_77d1`.
  2. **Collector Egress Panel**:
     - Expand the generated payload under `security`:
       ```json
       {"src": "p_77d1", "cat": "auth_fail", "count": 55, "win_s": 60, "risk": "high"}
       ```
     - Show that no username (e.g. `root`, `admin`) and no raw IP address appear in the wire payload.
  3. **SaaS Dashboard**:
     - Dashboard displays a high-risk security alert for entity `p_77d1`. The SaaS can reason over attack volume and correlate with other tenants without knowing customer network topology or employee credentials.

---

### Scenario 7: Duplicate or Out-of-Order Delivery
* **Objective**: Demonstrate idempotency and resilience to network anomalies.
* **Exact Command**:
  ```bash
  python injector.py inject dup-ooo
  ```
* **Step-by-Step Screen Walkthrough**:
  1. **Collector Transmission**:
     - Replays a previously acknowledged `payload_id` and shuffles chronological sequence.
  2. **SaaS Ingest Behavior**:
     - The Ingest API queries `(tenant_id, payload_id)` unique index.
     - Detects the duplicate, returns HTTP 200 Ack immediately without re-inserting or poisoning time-series metrics.
  3. **Dashboard Stability**:
     - TimescaleDB time-series charts remain completely smooth and deduplicated.

---

## 2. 60-Second Spoken Walkthrough of Egress Proof Panel

*(Spoken script for live presentation while screen sharing `http://localhost:8088`)*

> "Judges, welcome to the VeilOps Local Egress Proof Panel. This interface runs entirely on-premise inside the customer's private network.
>
> On the left, our **Leak Blocked counter is currently at zero**, and our **Outbox depth shows normal streaming**.
>
> First, notice the **Raw Data Tab**: here, the customer's on-premise diagnostic store holds unredacted logs with live passwords and planted AWS canary keys. These stay local with an automatic 24-hour purge.
>
> Now, look at the **Egress Wire Payloads Tab**: this is the only stream permitted to cross our network boundary. Notice that every single field is strictly typed: numbers, enums, and HMAC pseudonyms. There is no `message` or free-text field anywhere. Our Drain3 miner turned 400 lines of error logs into a 6-character template hash: `9f3a1c`.
>
> Finally, witness mathematical proof: when I click this green **'Verify Hash'** button, the collector sends a challenge to the SaaS Ingest API. SaaS recomputes the SHA-256 digest of what it stored, and as you see—**MATCH CONFIRMED 100%**. What left the customer site is byte-for-byte identical to what the cloud received. Privacy by construction."

---

## 3. Concise Answers to Judge Questions (<= 3 Sentences Each)

### Q1: What exactly leaves the customer environment?
> **Answer**: Only strictly typed metadata adhering to a JSON Schema with `additionalProperties: false`. This consists exclusively of metric window aggregates (mean, p95, min, max), 6-character Drain3 log template hashes with counts, sliding security risk counters, health state enums, and salted HMAC pseudonyms (`h_*`, `p_*`). Zero raw logs, packet payloads, or free-text strings ever cross the trust boundary.

### Q2: How are fields chosen and allowed?
> **Answer**: Fields are governed by a per-tenant signed YAML policy enforced by the collector's Egress Gate over a rigid wire schema allow-list. Any unrecognized field, over-long string, or unapproved metric name is hard-rejected at serialization time rather than silently stripped. Operators can dynamically restrict metric granularities per tenant, with drops recorded in the local ledger.

### Q3: How do you stop secrets or raw logs from leaking by accident?
> **Answer**: We employ defense-in-depth across four structural layers: the wire contract has no free-text fields where secrets can hide; Drain3 mines templates and strips parameters locally; an active scanner checks 100% of outbound serialized bytes for planted canaries and Shannon entropy ($H \ge 4.2$); and the SaaS ingest edge validates the schema a second time upon arrival.

### Q4: How are collectors authenticated and traffic encrypted?
> **Answer**: Each collector is issued a revocable mTLS client certificate via mutual TLS 1.3, binding the network transport directly to the tenant ID. Additionally, every payload is cryptographically signed at the application layer with the collector's private Ed25519 key and validated before queue ingestion.

### Q5: Can you show the last payload byte-for-byte?
> **Answer**: Yes. The Egress Proof Panel renders the exact canonical UTF-8 bytes and SHA-256 hash stored in the local outbox ledger for every egress event. Clicking 'Verify Hash' performs an on-the-fly reconciliation with the SaaS database to prove byte-level integrity.

---

## 4. Honest Limitations & Production Roadmap

| Dimension | Hackathon Prototype Implementation | Production Requirement |
| :--- | :--- | :--- |
| **Pseudonym Stability** | Stable HMAC-SHA256 pseudonyms per host/user across the session. | Dynamic per-tenant salt rotation every 90 days with differential-privacy noise added to count aggregates. |
| **Log Template Volume** | Drain3 template hashes reveal exact event frequency spikes. | Coarse frequency bucketing (e.g. logarithmic bands) for hyper-sensitive compliance tiers. |
| **Drain3 Online Clustering** | Online parse tree with heuristic regex wildcards for common formats. | Pre-trained enterprise log grammar models with human-in-the-loop template validation. |
| **Key Storage** | Ed25519 private key generated in collector container memory. | Hardware-backed cryptographic key isolation via TPM 2.0 or AWS CloudHSM / Vault. |
| **Egress Gate Auditing** | In-process byte scanner and local SQLite outbox. | Kernel-level eBPF network egress enforcement preventing any non-Egress-Gate socket binding. |

---

## 5. Three Innovation Talking Points (Bonus)

1. **Typed Egress Contract (Zero Free-Text Wire Schema)**:  
   While traditional observability relies on post-hoc redaction that inevitably leaks novel secret formats, VeilOps makes data leakage structurally impossible by removing all free-text fields (`message`, `log`, `payload`) from the wire schema entirely.

2. **Drain3 Log Fingerprints Instead of Log Lines**:  
   By executing online template mining on-premise, the cloud learns that *"Template `9f3a1c` increased 30x"*—delivering 100% of the operational signal needed for AIOps root-cause ranking without transmitting a single byte of customer log text.

3. **Active Canary Tripwire with Hash-Chained Proof Ledger**:  
   We pair an active pre-egress scanner that catches planted high-entropy honey-tokens with a local SHA-256 hash-chained ledger, giving security auditors mathematical proof that the telemetry stored in SaaS matches what left the site byte-for-byte.
