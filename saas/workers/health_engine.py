"""
VeilOps Tier 2 Health-State Engine Prototype
Person 2: SaaS and Reliability Architect

Implements:
1. Four health states: Excellent, Good, Fair, Poor (Worst-signal arbitration).
2. Heartbeat staleness detection: Fair at >15s (STALE_DATA), Poor at >60s (COLLECTOR_OFFLINE).
3. Hysteresis anti-flapping rule: requires 3 consecutive healthy evaluation windows before state improvement.
4. Deterministic reason codes and UTC transition logging.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Dict, List, Optional, Tuple


class HealthState(str, Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"


# Severity rank for worst-signal arbitration (higher is worse)
HEALTH_SEVERITY_RANK = {
    HealthState.EXCELLENT: 1,
    HealthState.GOOD: 2,
    HealthState.FAIR: 3,
    HealthState.POOR: 4,
}


@dataclass
class HealthTransitionRecord:
    collector_id: str
    tenant_id: str
    old_state: HealthState
    new_state: HealthState
    reason_codes: List[str]
    transition_time_utc: datetime
    consecutive_healthy_windows: int


class CollectorHealthEngine:
    """
    Evaluates collector health state based on:
    - Heartbeat freshness (15s Fair, 60s Poor)
    - Metric anomaly scores (|z| < 2.0 Excellent, 2.0-3.5 Good, >=3.5 Fair)
    - Network metrics (Packet loss <0.1% Excellent, 1-5% Fair, >5% Poor)
    - System thresholds (CPU/Mem >85% Fair, Disk >95% Poor)
    - 3-window hysteresis for state improvement
    """

    def __init__(self, hysteresis_required_windows: int = 3):
        self.hysteresis_required_windows = hysteresis_required_windows
        # State tracking: (tenant_id, collector_id) -> state dict
        self.collectors: Dict[Tuple[str, str], Dict] = {}
        self.transition_history: List[HealthTransitionRecord] = []

    def register_collector(self, tenant_id: str, collector_id: str, initial_time: datetime):
        key = (tenant_id, collector_id)
        self.collectors[key] = {
            "state": HealthState.EXCELLENT,
            "reason_codes": ["NOMINAL"],
            "last_heartbeat_utc": initial_time,
            "consecutive_healthy_windows": self.hysteresis_required_windows,
        }

    def record_heartbeat(self, tenant_id: str, collector_id: str, heartbeat_time: datetime):
        key = (tenant_id, collector_id)
        if key not in self.collectors:
            self.register_collector(tenant_id, collector_id, heartbeat_time)
        else:
            self.collectors[key]["last_heartbeat_utc"] = heartbeat_time

    def evaluate_health(
        self,
        tenant_id: str,
        collector_id: str,
        current_time_utc: datetime,
        metrics: Optional[Dict[str, float]] = None,
        robust_z: Optional[float] = None,
        has_critical_security_event: bool = False,
    ) -> Tuple[HealthState, List[str], Optional[HealthTransitionRecord]]:
        """
        Evaluates signals against deterministic thresholds and applies hysteresis.
        Returns: (current_state, reason_codes, transition_record_if_changed)
        """
        key = (tenant_id, collector_id)
        if key not in self.collectors:
            self.register_collector(tenant_id, collector_id, current_time_utc)

        coll = self.collectors[key]
        last_hb = coll["last_heartbeat_utc"]
        silence_seconds = (current_time_utc - last_hb).total_seconds()

        evaluated_signals: List[Tuple[HealthState, str]] = []

        # 1. Staleness Rules
        if silence_seconds >= 60.0:
            evaluated_signals.append((HealthState.POOR, "COLLECTOR_OFFLINE"))
        elif silence_seconds >= 15.0:
            evaluated_signals.append((HealthState.FAIR, "STALE_DATA"))

        # 2. Critical Security
        if has_critical_security_event:
            evaluated_signals.append((HealthState.POOR, "AUTH_BRUTE_FORCE_SUSPECT"))

        # 3. Telemetry Metrics Evaluation
        if metrics:
            packet_loss = metrics.get("packet_loss_pct", 0.0)
            if packet_loss > 5.0:
                evaluated_signals.append((HealthState.POOR, "PACKET_LOSS_ELEVATED"))
            elif packet_loss > 1.0:
                evaluated_signals.append((HealthState.FAIR, "PACKET_LOSS_ELEVATED"))

            cpu = metrics.get("cpu_pct", 0.0)
            if cpu > 85.0:
                evaluated_signals.append((HealthState.FAIR, "CPU_BASELINE_DEV"))

            mem = metrics.get("mem_pct", 0.0)
            if mem > 85.0:
                evaluated_signals.append((HealthState.FAIR, "MEM_BASELINE_DEV"))

            disk = metrics.get("disk_pct", 0.0)
            if disk > 95.0:
                evaluated_signals.append((HealthState.POOR, "DISK_CAPACITY_WARN"))

        # 4. Anomaly Z-Score Evaluation
        if robust_z is not None:
            abs_z = abs(robust_z)
            if abs_z >= 3.5:
                evaluated_signals.append((HealthState.FAIR, "CPU_BASELINE_DEV"))
            elif abs_z >= 2.0:
                evaluated_signals.append((HealthState.GOOD, "CPU_BASELINE_DEV"))

        # Worst-Signal Arbitration
        if not evaluated_signals:
            raw_state = HealthState.EXCELLENT
            reasons = ["NOMINAL"]
        else:
            # Sort by highest severity rank
            evaluated_signals.sort(key=lambda s: HEALTH_SEVERITY_RANK[s[0]], reverse=True)
            raw_state = evaluated_signals[0][0]
            reasons = list(dict.fromkeys(r[1] for r in evaluated_signals if r[0] == raw_state))

        current_active_state = coll["state"]
        transition_record: Optional[HealthTransitionRecord] = None

        # Check Hysteresis:
        # If signal is WORSE: degrade immediately
        # If signal is BETTER: require 3 consecutive healthy windows
        if HEALTH_SEVERITY_RANK[raw_state] > HEALTH_SEVERITY_RANK[current_active_state]:
            # Immediate downgrade
            transition_record = HealthTransitionRecord(
                collector_id=collector_id,
                tenant_id=tenant_id,
                old_state=current_active_state,
                new_state=raw_state,
                reason_codes=reasons,
                transition_time_utc=current_time_utc,
                consecutive_healthy_windows=0,
            )
            coll["state"] = raw_state
            coll["reason_codes"] = reasons
            coll["consecutive_healthy_windows"] = 0
            self.transition_history.append(transition_record)

        elif HEALTH_SEVERITY_RANK[raw_state] < HEALTH_SEVERITY_RANK[current_active_state]:
            # Improvement candidate: increment consecutive counter
            coll["consecutive_healthy_windows"] += 1
            if coll["consecutive_healthy_windows"] >= self.hysteresis_required_windows:
                # State improved after meeting hysteresis criteria
                transition_record = HealthTransitionRecord(
                    collector_id=collector_id,
                    tenant_id=tenant_id,
                    old_state=current_active_state,
                    new_state=raw_state,
                    reason_codes=reasons,
                    transition_time_utc=current_time_utc,
                    consecutive_healthy_windows=coll["consecutive_healthy_windows"],
                )
                coll["state"] = raw_state
                coll["reason_codes"] = reasons
                self.transition_history.append(transition_record)
        else:
            # Same state: reset healthy windows counter if nominal
            if raw_state == HealthState.EXCELLENT:
                coll["consecutive_healthy_windows"] = self.hysteresis_required_windows
            coll["reason_codes"] = reasons

        return coll["state"], coll["reason_codes"], transition_record
