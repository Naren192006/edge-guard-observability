"""
VeilOps AIOps Phase 3 - Streaming Engine & Payload Consumer

Features:
1. Ingests accepted wire-schema payloads (from Redis Streams or direct pipeline).
2. Evaluates seasonal baselines (EWMA median & MAD) and River HSTrees joint scoring.
3. Emits enriched contextual MetricAlerts within 15 seconds of threshold breaches.
4. Groups cascading alerts into single incidents via NetworkX topology + Union-Find.
5. Ranks root causes (earliest onset, topology position, blast radius) and generates Evidence Cards.
6. Manages closed-loop remediation workflows with auto-rollback.
7. Tracks live alert-noise reduction metrics.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Tuple
import json
import logging

from .baselines import SeasonalEWMABaseline, SustainedDeviationDetector, JointMultiSignalHSTrees
from .correlate import TopologyGraph, IncidentCorrelator
from .rank import CauseRanker
from .recommendations import RecommendationEngine, RULE_LIBRARY
from .remediation import RemediationAction
from .schemas import (
    MetricAlert,
    Severity,
    RiskLevel,
    EvidenceCard,
    NoiseReductionMetric,
    RemediationStatus,
)

logger = logging.getLogger("veilops.aiops.consumer")


class AIOpsEngine:
    """
    Central operational intelligence engine.
    Processes typed telemetry payloads across all tenants.
    """

    def __init__(
        self,
        topology: Optional[TopologyGraph] = None,
        z_threshold: float = 3.5,
        window_size: int = 5,
        min_breach_count: int = 3,
    ):
        self.topology = topology or self._build_default_topology()
        self.detector = SustainedDeviationDetector(
            z_threshold=z_threshold,
            window_size=window_size,
            min_breach_count=min_breach_count,
        )
        self.hstrees = JointMultiSignalHSTrees(n_trees=25, height=8, window_size=100)
        self.correlator = IncidentCorrelator(
            topology=self.topology,
            max_time_window_seconds=120,
            max_hop_distance=2,
            recovery_seconds_to_close=300,
        )
        self.ranker = CauseRanker(topology=self.topology)
        self.recommender = RecommendationEngine()

        # Operational state storage
        self.raw_alerts_total: int = 0
        self.incidents_total: int = 0
        self.active_evidence_cards: Dict[str, EvidenceCard] = {}
        self.remediation_actions: Dict[str, RemediationAction] = {}
        self.alert_history: List[MetricAlert] = []

    def _build_default_topology(self) -> TopologyGraph:
        """Constructs canonical enterprise infrastructure topology DAG."""
        topo = TopologyGraph()
        # Edge switch -> Gateway -> Database & Services
        topo.add_component("edge_sw2", "switch", region="ap-south")
        topo.add_component("api_gw", "gateway", region="ap-south")
        topo.add_component("orders_db", "database", region="ap-south")
        topo.add_component("h_4af29c", "host", region="ap-south")
        topo.add_component("p_77d1", "service", region="ap-south")

        topo.add_dependency("edge_sw2", "api_gw")
        topo.add_dependency("api_gw", "orders_db")
        topo.add_dependency("api_gw", "p_77d1")
        topo.add_dependency("h_4af29c", "orders_db")
        return topo

    def process_payload(self, payload: Dict[str, Any]) -> List[EvidenceCard]:
        """
        Processes a single signed, schema-validated wire payload.
        Returns newly generated or updated Evidence Cards.
        """
        tenant_id = payload.get("tenant_id", "default_tenant")
        collector_id = payload.get("collector_id", "default_collector")
        event_time_str = payload.get("event_time_utc")
        if event_time_str:
            event_time = datetime.fromisoformat(event_time_str.replace("Z", "+00:00"))
        else:
            event_time = datetime.now(timezone.utc)

        # 1. Process Metrics (5-second tumbling windows)
        metrics = payload.get("metrics", [])
        new_alerts: List[MetricAlert] = []

        # Multi-signal feature vector accumulator for HSTrees
        multi_signal_dict: Dict[str, float] = {}

        for m in metrics:
            src = m.get("src", "unknown_source")
            metric_name = m.get("name", "unknown_metric")
            mean_val = float(m.get("mean", 0.0))
            p95_val = float(m.get("p95", mean_val))

            multi_signal_dict[metric_name] = p95_val

            # Evaluate univariate robust z-score & sustained deviation
            res = self.detector.ingest(src, metric_name, p95_val, event_time)
            if res["is_sustained"]:
                self.raw_alerts_total += 1
                alert_id = f"ALT-{self.raw_alerts_total:05d}"
                alert = MetricAlert(
                    alert_id=alert_id,
                    component_id=src,
                    metric_name=metric_name,
                    severity=Severity(res["severity"]),
                    observed_value=p95_val,
                    baseline_value=res["median"],
                    z_score=res["robust_z"],
                    onset_time_utc=event_time,
                    category="metric_baseline_deviation",
                )
                new_alerts.append(alert)
                self.alert_history.append(alert)

        # 2. Process Multi-Signal Joint Anomaly via HSTrees
        if multi_signal_dict:
            hst_score = self.hstrees.learn_and_score(multi_signal_dict)
            if hst_score >= 0.70:
                self.raw_alerts_total += 1
                alert_id = f"ALT-{self.raw_alerts_total:05d}"
                primary_src = metrics[0].get("src", "system") if metrics else "system"
                alert = MetricAlert(
                    alert_id=alert_id,
                    component_id=primary_src,
                    metric_name="joint_multisignal_score",
                    severity=Severity.HIGH,
                    observed_value=round(hst_score, 3),
                    baseline_value=0.35,
                    z_score=round(hst_score * 5.0, 2),
                    onset_time_utc=event_time,
                    category="multivariate_covariance_anomaly",
                )
                new_alerts.append(alert)
                self.alert_history.append(alert)

        # 3. Process Security Signals (e.g. auth failure burst)
        sec_events = payload.get("security", [])
        for s in sec_events:
            src = s.get("src", "p_unknown")
            cat = s.get("cat", "sec_event")
            count = int(s.get("count", 0))
            risk = s.get("risk", "low")

            if risk in ["high", "critical"] or count >= 40:
                self.raw_alerts_total += 1
                alert_id = f"ALT-{self.raw_alerts_total:05d}"
                alert = MetricAlert(
                    alert_id=alert_id,
                    component_id=src,
                    metric_name="auth_fail_velocity",
                    severity=Severity.HIGH if risk == "high" else Severity.CRITICAL,
                    observed_value=float(count),
                    baseline_value=2.0,
                    z_score=6.5,
                    onset_time_utc=event_time,
                    category="security_risk",
                )
                new_alerts.append(alert)
                self.alert_history.append(alert)

        # 4. Ingest new alerts into Topology Incident Correlator
        for alert in new_alerts:
            self.correlator.ingest_alert(alert)

        # 5. Group Incidents via Union-Find and Generate Evidence Cards
        grouped_clusters = self.correlator.group_incidents()
        generated_cards: List[EvidenceCard] = []

        for cluster in grouped_clusters:
            inc_id = cluster["incident_id"]
            affected = cluster["affected_components"]
            c_alerts = cluster["alerts"]

            # Multi-factor cause ranking
            likely_cause, alternatives, confidence = self.ranker.rank_causes(c_alerts, affected)

            # Build full Evidence Card
            noise_metric = cluster["noise_reduction"]
            card = self.recommender.build_evidence_card(
                incident_id=inc_id,
                severity=cluster["severity"],
                opened_at_utc=cluster["opened_at_utc"],
                affected_components=affected,
                alerts=c_alerts,
                likely_cause=likely_cause,
                alternatives=alternatives,
                confidence=confidence,
                noise_reduction=noise_metric,
            )

            self.active_evidence_cards[inc_id] = card
            generated_cards.append(card)

            # Auto-propose remediation action
            if inc_id not in self.remediation_actions:
                action = RemediationAction(
                    action_id=f"ACT-{inc_id.replace('INC-', '')}",
                    incident_id=inc_id,
                    tenant_id=tenant_id,
                    target_component=likely_cause.component_id,
                    runbook_id=card.suggested_action.runbook_id,
                    risk_level=card.suggested_action.risk_level,
                )
                # Auto-run policy check against standard allowed runbooks
                allowed_runbooks = [r.runbook_id for r in RULE_LIBRARY]
                action.policy_check(allowed_runbooks=allowed_runbooks, is_in_change_window=True)
                self.remediation_actions[inc_id] = action

        self.incidents_total = len(self.active_evidence_cards)
        return generated_cards

    def get_noise_reduction_stats(self) -> Dict[str, Any]:
        """Returns fleet-wide alert noise reduction statistics."""
        if self.raw_alerts_total == 0:
            return {"raw_alerts": 0, "incidents": 0, "reduction_ratio_pct": 0.0}
        ratio = ((self.raw_alerts_total - self.incidents_total) / self.raw_alerts_total) * 100.0
        return {
            "raw_alerts": self.raw_alerts_total,
            "incidents": self.incidents_total,
            "reduction_ratio_pct": round(max(0.0, ratio), 1),
        }
