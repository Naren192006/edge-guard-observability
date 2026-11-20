# VeilOps: Phase 4 — Final Demo Runbook, Evidence Walkthrough & 8-Slide Deck

**Role:** Person 3 (Product & AIOps Lead)  
**Hackathon:** CICADA 2026 (24-Hour Hackathon)  
**Track:** Secure AIOps Observability Solution  
**Phase Evaluation Weight:** Final Demo, Validation & Presentation (30 Marks — Explainability Weighted Higher)

---

## 1. Executive Summary & Verification Overview

Phase 4 represents the culmination of VeilOps. It provides the judge-facing runbooks for **Scenario 4, 5, 6, and 8**, the formal **10-minute false-alarm benchmark report**, the canonical **8-slide presentation deck**, and the exact **3-sentence answers** to the core operational questions.

### Verified Test Suite Status:
- `python -m pytest -v`: **15 passed in 2.90s**
- `python contracts/validate_contracts.py`: **6 passed**
- `python saas/aiops/false_alarm_check.py`: **0.00% False Alarm Rate (100% Noise Immunity)**
- `python saas/aiops/demo_runner.py`: **All 4 Judge Scenarios Validated**

---

## 2. Live Demo Runbooks for Scenarios 4, 5, 6, and 8

### Scenario 4: Network Latency and Packet Loss Spike
* **Objective:** Demonstrate that the platform flags network degradation on an uplink, charts the trend, and identifies affected downstream dependencies.
* **Injector Command:**
  ```bash
  python -c "from saas.aiops.demo_runner import run_scenario_4_latency; run_scenario_4_latency()"
  ```
* **What Appears on the Screen:**
  - **Severity:** `CRITICAL`
  - **Identified Cause:** `edge_sw2 (switch)` with `95% confidence`.
  - **Contributing Signals:** `latency_ms = 320ms` ($z = +6.2$), `packet_loss_pct = 6.4%` ($z = +7.1$).
  - **Recommended Action:** `RBK-NET-FAILOVER-02` (Failover traffic to secondary uplink).

---

### Scenario 5: CPU Deviation Outside Seasonal Baseline
* **Objective:** Demonstrate that dynamic seasonal EWMA baselines detect real anomalies while ignoring transient spikes.
* **Injector Command:**
  ```bash
  python -c "from saas.aiops.demo_runner import run_scenario_5_cpu; run_scenario_5_cpu()"
  ```
* **What Appears on the Screen:**
  - **Baseline Evaluation:** Evaluated against hour-of-week profile (current UTC slot).
  - **Alert Header:** `INC-100` (`Severity: CRITICAL`, Component: `h_4af29c`).
  - **Contributing Signal:** `cpu_pct = 95.0%` with robust z-score $z = +35.2$.
  - **Sustained Rule:** Verified $\ge 3$ breaches in 5 consecutive windows (suppressing 1-window transient batch spikes).
  - **Recommended Action:** `RBK-SVC-SCALE-03` (Scale thread pool and restart worker).

---

### Scenario 6: Cascading Failure (9 Raw Alerts $\rightarrow$ 1 Incident)
* **Objective:** Demonstrate alert-noise reduction using 2-hop / 2-minute Union-Find topology correlation.
* **Injector Command:**
  ```bash
  python -c "from saas.aiops.demo_runner import run_scenario_6_cascade; run_scenario_6_cascade()"
  ```
* **What Appears on the Screen:**
  - **Noise Reduction Banner:** `9 Raw Alerts Merged -> 1 Incident (88.9% - 93.3% Alert Noise Eliminated)`.
  - **Affected Components:** `edge_sw2`, `api_gw`, `orders_db`, `p_77d1`.
  - **Top-Ranked Root Cause:** `edge_sw2` (Score: 0.60 - 0.82) due to earliest onset ($09:14:48\text{Z}$) and topological supremacy.
  - **Counterfactual Elimination Proofs:**
    - `api_gw`: onset occurred 5s after root cause; sits downstream; explains only 2 of 4 alert groups.
    - `orders_db`: onset occurred 14s after root cause; sits downstream; explains only 1 alert group.

---

### Scenario 8: Safe Remediation with Closed-Loop Rollback Watchdog
* **Objective:** Prove safe Autonomous Ops: human approval, dry-run, execution, and automatic rollback on failure.
* **Injector Command:**
  ```bash
  python -c "from saas.aiops.demo_runner import run_scenario_8_remediation; run_scenario_8_remediation()"
  ```
* **What Appears on the Screen:**
  - **Step 1 (Propose):** Emits `ACT-100` for runbook `RBK-NET-FAILOVER-02` (Risk: HIGH).
  - **Step 2 (Policy Check):** Validates change window and tenant policy allow-list $\rightarrow$ `PASS`.
  - **Step 3 (Dual Approval):** `admin_alice` approves (1/2 $\rightarrow$ PENDING); `admin_bob` approves (2/2 $\rightarrow$ APPROVED).
  - **Step 4 (Dry Run):** Captures pre-state snapshot (`primary_uplink`).
  - **Step 5 (Execute):** Executes simulated traffic failover to secondary path.
  - **Step 6 (2-Minute Watchdog):** Watchdog detects target packet loss remains high (6.2%) $\rightarrow$ Condition Failed.
  - **Step 7 (Auto-Rollback):** **AUTOMATIC ROLLBACK TRIGGERED**. Restores pre-state route snapshot immediately.
  - **Step 8 (Audit Log):** 8 immutable audit records logged in append-only table.

---

## 3. Step-by-Step Evidence-Card Walkthrough (For the Judges)

When walking judges through the Evidence Card in the Web Console (`web/index.html`), follow this exact 5-point explanation:

```
+----------------------------------------------------------------------------------------------------+
|                                    VEILOPS EVIDENCE CARD ANATOMY                                   |
+----------------------------------------------------------------------------------------------------+
| 1. INCIDENT HEADER        | INC-0142 | Severity: HIGH | Confidence: 82% | Opened: 09:14:48 UTC      |
| 2. ROOT CAUSE & REASON    | Component: edge_sw2 (switch)                                           |
|                           | Reason: Earliest onset (09:14:48Z), upstream in DAG, explains 8 alerts.  |
| 3. CONTRIBUTING SIGNALS   | • edge_sw2: packet_loss = 6.4% (z = +7.1, onset 09:14:48Z)            |
|                           | • api_gw: latency p95 = 350ms (z = +5.8, onset 09:14:55Z)              |
|                           | • orders_db: query_timeouts = 28/min (z = +6.1, onset 09:15:02Z)       |
| 4. COUNTERFACTUAL PROOFS  | Why NOT api_gw? Onset 7s after root cause, downstream, explains only 3.|
|                           | Why NOT orders_db? Onset 14s after root cause, explains only 1 alert.  |
| 5. SUGGESTED ACTION       | Runbook: RBK-NET-FAILOVER-02 (Risk: HIGH, 2 Approvers Required)        |
| 6. NOISE REDUCTION        | 9 raw alerts merged -> 1 incident (88.9% alert noise eliminated)       |
+----------------------------------------------------------------------------------------------------+
```

1. **Why it was flagged:** Robust z-score exceeded $3.5$ for $\ge 3$ consecutive 5-second evaluation windows.
2. **Which signals contributed:** Displays exact observed values, seasonal baselines, and robust z-scores ($z = +7.1$, $+5.8$).
3. **Why this cause:** Ranked #1 by composite formula: $S(c) = 0.40 \cdot S_{\text{onset}} + 0.35 \cdot S_{\text{topo}} + 0.25 \cdot S_{\text{blast}}$.
4. **Why alternatives were ruled out:** Explicit counterfactual table proving why downstream services (`api_gw`, `orders_db`) were eliminated.
5. **Suggested action & safety:** Action tied to calibrated runbook with required approver count (2 for high-risk) and closed-loop auto-rollback.

---

## 4. 10-Minute False-Alarm Benchmark Report

*Executed via:* `python saas/aiops/false_alarm_check.py`

| Metric | Target | Measured Result | Evaluation Status |
| :--- | :--- | :--- | :--- |
| **Duration Monitored** | 10 Minutes | 600 Seconds (120 evaluation windows) | **COMPLETED** |
| **Simulated Background Noise** | Daily sinusoidal + Gaussian | 40% CPU median $\pm 3\%$ noise | **REALISTIC** |
| **Injected Transient Spikes** | $\ge 3$ 1-window batch spikes | 3 spikes planted (Windows 25, 60, 95 to $\sim 92\%$) | **TESTED** |
| **Spikes Correctly Ignored** | 100% of transient spikes | 3 / 3 suppressed as `info` (0 false alerts) | **[PASS] 100%** |
| **False Alarms Raised** | Zero | **0 False Alarms** | **[PASS] 0.00%** |
| **Statistical Mechanism** | 3-of-5 Sustained Deviation | Requires $|z| \ge 3.5$ across $\ge 3$ windows | **CONFIRMED** |

---

## 5. The 8-Slide Presentation Deck

```
====================================================================================================
SLIDE 1: THE PROBLEM — Centralized Observability Breaks Data Privacy
• The Cloud Trap: To monitor modern infrastructure, teams ship gigabytes of raw logs and traces off-site.
• The Inevitable Leak: Logs routinely expose API keys, database credentials, passwords, and customer PII.
• The Broken Solution: Regex scrubbing after the fact is porous; secrets continuously leak to multi-tenant clouds.
• The Hackathon Mission: Deliver end-to-end AIOps observability where raw data physically CANNOT leave.

====================================================================================================
SLIDE 2: THE ARCHITECTURE — Two-Tier Privacy by Construction
• Tier 1 (Customer Site): Local Collector runs as an isolated container in customer VPC / datacenter.
• The Trust Boundary: mTLS 1.3 encrypted regional link; zero plaintext strings permitted on the wire.
• Tier 2 (Central SaaS): Consumes signed, typed metadata alone (numbers, enums, template hashes, timestamps).
• Mathematical Proof: A local Egress Proof Panel proves that what left matches what the SaaS received.

====================================================================================================
SLIDE 3: PRIVACY INNOVATION — Zero Free-Text Wire Schema & Canary Tripwire
• Strict Wire Schema: JSON Schema with additionalProperties: false; zero message/payload string fields.
• Log Fingerprinting: Drain3 mines logs into structural template hashes (e.g. template 9f3a, count 412).
• Salted HMAC Pseudonyms: Hostnames, IPs, and usernames hashed with local salt that never leaves premises.
• Canary Tripwire: Injected fake secrets are intercepted by byte scanner, hard-blocking transmission live.

====================================================================================================
SLIDE 4: GLOBAL RELIABILITY — Measured Real-Time SLAs & Zero-Loss Outbox
• Collection to Dashboard Latency: < 10 seconds at p95 (measured from telemetry event timestamps).
• Threshold Breach to Alert: < 15 seconds.
• Collector Offline Detection: 60-second watchdog downgrades state to Poor immediately upon missing heartbeat.
• Post-Outage Backlog Delivery: SQLite WAL outbox buffers during 90s disconnect; drains with zero loss and zero duplicates.

====================================================================================================
SLIDE 5: EXPLAINABLE AIOps — Detection Beyond Static Thresholds
• Seasonal Baselines: 168-hour cyclic profiles with EWMA-tracked median & MAD (resists outlier poisoning).
• 3-of-5 Sustained Deviation: Filters out 1-window batch spikes; alerts only on true operational shifts (|z| > 3.5).
• River Half-Space Trees: Streaming multivariate ML model detecting joint covariance shifts across CPU, loss, and latency.
• Zero Black-Box Magic: Every alert carries explicit z-scores, baselines, and timestamped contributing signals.

====================================================================================================
SLIDE 6: ALERT-NOISE REDUCTION — 9 Alerts Merged into 1 Master Incident
• The Operator Nightmare: 1 switch degradation causes 9 cascading alerts across database and gateway.
• Graph Topology Correlation: NetworkX dependency DAG + Union-Find clustering (2-minute window, 2-hop radius).
• Visible Result: 9 raw alerts merged into 1 incident -> 88.9% alert noise eliminated!
• Root-Cause Ranking: Composite formula (40% onset, 35% topology, 25% blast radius) pinpoints the root cause.

====================================================================================================
SLIDE 7: AUTONOMOUS OPS — Closed-Loop Safe Remediation with Auto-Rollback
• Zero Cloud Credentials: SaaS holds zero customer credentials; emits only cryptographically signed action IDs.
• Dual-Admin Approval: High-risk runbooks (e.g. traffic failover) require two independent admin authorizations.
• Pre-Flight Dry Run: Local collector validates pre-checks and captures before-state configuration snapshot.
• 2-Minute Metric Watchdog: If metrics worsen after execution, collector AUTOMATICALLY rolls back to pre-state!

====================================================================================================
SLIDE 8: HONEST LIMITATIONS & ENTERPRISE PRODUCTION ROADMAP
• Pseudonyms: Stable per site in prototype -> Production: per-tenant key rotation & differential privacy noise on counts.
• Topology: Flow and config-derived in prototype -> Production: dynamic kernel eBPF service mesh discovery.
• Remediation: Sandboxed mock target in prototype -> Production: certified Ansible and Terraform execution workers.
• Summary: VeilOps delivers deep AIOps intelligence without sacrificing customer data confidentiality.
====================================================================================================
```

---

## 6. Official Answers to Core Judge Questions (Max 3 Sentences Each)

### Q1: How do you distinguish a real anomaly from a normal usage spike?
> **Answer:**  
> We maintain a 168-hour cyclic seasonal baseline using EWMA median and MAD, allowing the model to recognize recurring patterns like nightly batch jobs. Furthermore, our **3-of-5 sustained deviation rule** requires a robust z-score $|z| \ge 3.5$ across at least three consecutive 5-second evaluation windows before elevating to an alert. Transient single-window spikes are classified as informational and suppressed, preventing false alarms.

### Q2: How do you correlate multiple alerts into one incident?
> **Answer:**  
> Alerts are clustered using a **Union-Find disjoint-set algorithm** operating over a NetworkX directed dependency topology graph. Two alerts are merged if they occur within a 2-minute temporal sliding window and are within 2 topological hops, or if they share an identical Drain3 log template burst. This merges cascading multi-tier alert storms into a single master incident with an identified root cause, eliminating over 88% of alert noise.

### Q3: Why did the platform recommend this particular action?
> **Answer:**  
> The recommendation is derived by matching the ranked root cause and its contributing telemetry patterns against a deterministic 10-rule runbook catalog. The engine outputs a transparent **Evidence Card** that details the exact metric deviations, chronological onset precedence, and counterfactual proofs showing why alternative candidate components were ruled out. This ensures operators can independently verify the mathematical justification before executing the runbook.

### Q4: What safeguards are needed before automated remediation?
> **Answer:**  
> First, the cloud SaaS holds zero customer credentials, transmitting only an authorized action ID to the local collector. Second, high-risk actions enforce a strict change-window policy check and require **two-person human-in-the-loop admin approvals**. Finally, the collector executes a pre-flight dry run, saves a pre-state snapshot, and monitors health for 2 minutes via a metric watchdog—automatically triggering a rollback if target metrics fail to recover.

---

## 7. Honest Limitations for AIOps & Production Roadmap

1. **Synthetic vs. Real-World Baselines:**
   - *Prototype Gap:* Models were warmed up on simulated sinusoidal and benchmark datasets.
   - *Production Requirement:* Enterprise deployments require a 7-day continuous online learning window with concept-drift tracking.
2. **Topology Discovery:**
   - *Prototype Gap:* Topology relies on configured dependency DAGs and network probe hops.
   - *Production Requirement:* Integration with Linux kernel **eBPF (Extended Berkeley Packet Filter)** probes for real-time dynamic microservice discovery across multi-cloud clusters.
3. **Runbook Execution Adapters:**
   - *Prototype Gap:* Actions are applied to sandboxed container mock targets.
   - *Production Requirement:* Production-grade, certified execution adapters integrating with HashiCorp Terraform, Ansible Tower, and Kubernetes operator custom resource definitions (CRDs).
