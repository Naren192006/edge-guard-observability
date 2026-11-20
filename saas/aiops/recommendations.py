"""
VeilOps AIOps Phase 2 - Rule Library & Evidence Card Generator

Fulfills:
1. 10 cause-pattern -> recommendation mappings.
2. Complete Evidence-Card assembly with contributing signals, robust z-scores,
   and counterfactual elimination reasons.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional
from .schemas import (
    EvidenceCard,
    LikelyCause,
    AlternativeElimination,
    SuggestedAction,
    ContributingSignal,
    MetricAlert,
    Severity,
    RiskLevel,
    RecommendationRule,
    NoiseReductionMetric,
)


# The canonical 10 cause-pattern to recommendation rules
RULE_LIBRARY: List[RecommendationRule] = [
    RecommendationRule(
        rule_id="RULE_01",
        pattern_description="Disk capacity growth rate spike coupled with error template surge",
        target_metric="disk_used_pct",
        threshold_condition="disk_used_pct > 85.0 and error_templates > 100",
        runbook_id="RBK-DISK-PURGE-01",
        action_description="Verify active log rotation rules and purge orphaned temporary volumes on target host.",
        risk_level=RiskLevel.LOW,
        approvers_needed=1,
    ),
    RecommendationRule(
        rule_id="RULE_02",
        pattern_description="Packet loss spike plus p95 latency surge across uplink or network switch",
        target_metric="packet_loss_pct",
        threshold_condition="packet_loss_pct > 3.0 and latency_ms > 200",
        runbook_id="RBK-NET-FAILOVER-02",
        action_description="Inspect physical/virtual uplink errors and initiate traffic failover to secondary path.",
        risk_level=RiskLevel.HIGH,
        approvers_needed=2,
    ),
    RecommendationRule(
        rule_id="RULE_03",
        pattern_description="CPU baseline deviation coupled with thread-pool saturation error template",
        target_metric="cpu_pct",
        threshold_condition="cpu_pct z_score > 3.5 and thread_pool_saturation == True",
        runbook_id="RBK-SVC-SCALE-03",
        action_description="Scale worker thread-pool replicas and gracefully restart degraded worker process.",
        risk_level=RiskLevel.MEDIUM,
        approvers_needed=1,
    ),
    RecommendationRule(
        rule_id="RULE_04",
        pattern_description="Authentication failure velocity breach from pseudonymous entity (>40/min)",
        target_metric="auth_fail_velocity",
        threshold_condition="auth_failures > 40 in 60s",
        runbook_id="RBK-SEC-RATELIMIT-04",
        action_description="Enforce temporary rate-limiting or firewall drop rule against pseudonymous entity at edge gateway.",
        risk_level=RiskLevel.MEDIUM,
        approvers_needed=1,
    ),
    RecommendationRule(
        rule_id="RULE_05",
        pattern_description="Sustained memory growth indicating progressive memory leak",
        target_metric="memory_pct",
        threshold_condition="memory_pct > 88.0 and sustained_trend == True",
        runbook_id="RBK-MEM-RESTART-05",
        action_description="Trigger automated heap-profile capture followed by rolling restart of container pod.",
        risk_level=RiskLevel.MEDIUM,
        approvers_needed=1,
    ),
    RecommendationRule(
        rule_id="RULE_06",
        pattern_description="Database connection pool exhaustion and query latency degradation",
        target_metric="db_connections_active",
        threshold_condition="pool_utilization > 95.0 and query_latency_ms > 500",
        runbook_id="RBK-DB-POOL-06",
        action_description="Expand max connection pool threshold and terminate hung long-running idle transactions.",
        risk_level=RiskLevel.HIGH,
        approvers_needed=2,
    ),
    RecommendationRule(
        rule_id="RULE_07",
        pattern_description="DNS resolution latency degradation across external probes",
        target_metric="dns_latency_ms",
        threshold_condition="dns_latency_ms > 300",
        runbook_id="RBK-DNS-FALLBACK-07",
        action_description="Switch core resolver priority to secondary upstream recursive DNS server and flush cache.",
        risk_level=RiskLevel.LOW,
        approvers_needed=1,
    ),
    RecommendationRule(
        rule_id="RULE_08",
        pattern_description="Collector local outbox queue depth accumulation during healthy network",
        target_metric="queue_depth",
        threshold_condition="queue_depth > 500 and network_latency_ms < 50",
        runbook_id="RBK-COLLECTOR-TUNE-08",
        action_description="Increase local collector worker worker concurrency and expand memory buffer allocation.",
        risk_level=RiskLevel.LOW,
        approvers_needed=1,
    ),
    RecommendationRule(
        rule_id="RULE_09",
        pattern_description="TLS/mTLS certificate impending expiration indicator (<7 days remaining)",
        target_metric="cert_expiry_days",
        threshold_condition="days_to_expiry < 7",
        runbook_id="RBK-CERT-RENEW-09",
        action_description="Initiate automated zero-downtime certificate rotation via step-ca / ACME integration.",
        risk_level=RiskLevel.LOW,
        approvers_needed=1,
    ),
    RecommendationRule(
        rule_id="RULE_10",
        pattern_description="Cascading 503 downstream service mesh timeout errors from upstream microservice",
        target_metric="http_503_rate",
        threshold_condition="error_rate > 15.0 and downstream_cascade == True",
        runbook_id="RBK-MESH-BREAKER-10",
        action_description="Trip Istio/Envoy circuit breaker on failing upstream microservice and route to fallback stub.",
        risk_level=RiskLevel.HIGH,
        approvers_needed=2,
    ),
]


class RecommendationEngine:
    """Matches incident patterns to recommendations and builds Evidence Cards."""

    def __init__(self, rules: Optional[List[RecommendationRule]] = None):
        self.rules = rules or RULE_LIBRARY

    def match_rule(self, alerts: List[MetricAlert]) -> SuggestedAction:
        """Finds the best matching runbook rule based on alert metrics."""
        metric_names = {a.metric_name for a in alerts}

        if "packet_loss_pct" in metric_names or "latency_ms" in metric_names:
            rule = self.rules[1]  # RULE_02 Uplink failover
        elif "auth_fail_velocity" in metric_names or any("auth" in a.metric_name for a in alerts):
            rule = self.rules[3]  # RULE_04 Rate limit
        elif "cpu_pct" in metric_names:
            rule = self.rules[2]  # RULE_03 Scale/restart
        elif "disk_used_pct" in metric_names:
            rule = self.rules[0]  # RULE_01 Disk purge
        elif "memory_pct" in metric_names:
            rule = self.rules[4]  # RULE_05 Memory restart
        else:
            rule = self.rules[0]

        return SuggestedAction(
            runbook_id=rule.runbook_id,
            description=rule.action_description,
            risk_level=rule.risk_level,
            requires_approval=True,
            approvers_required=rule.approvers_needed,
            automated_safe_simulation=True,
        )

    def build_evidence_card(
        self,
        incident_id: str,
        severity: Severity,
        opened_at_utc: datetime,
        affected_components: List[str],
        alerts: List[MetricAlert],
        likely_cause: LikelyCause,
        alternatives: List[AlternativeElimination],
        confidence: float,
        noise_reduction: Optional[NoiseReductionMetric] = None,
    ) -> EvidenceCard:
        """Assembles a complete, schema-compliant EvidenceCard."""
        contributing_signals = [
            ContributingSignal(
                source=a.component_id,
                metric_or_pattern=a.metric_name,
                observed_value=a.observed_value,
                baseline_value=a.baseline_value,
                z_score=round(a.z_score, 2),
                onset_time_utc=a.onset_time_utc,
            )
            for a in alerts
        ]

        suggested_action = self.match_rule(alerts)

        return EvidenceCard(
            incident_id=incident_id,
            severity=severity,
            opened_at_utc=opened_at_utc,
            affected_components=affected_components,
            likely_cause=likely_cause,
            confidence=confidence,
            contributing_signals=contributing_signals,
            why_this_cause=likely_cause.reasoning,
            why_not_alternatives=alternatives,
            suggested_action=suggested_action,
            noise_reduction=noise_reduction,
        )
