"""
Unit tests for VeilOps Phase 2 AIOps Engine
"""

from datetime import datetime, timezone, timedelta
import pytest

from saas.aiops import (
    SeasonalEWMABaseline,
    SustainedDeviationDetector,
    JointMultiSignalHSTrees,
    TopologyGraph,
    IncidentCorrelator,
    CauseRanker,
    RecommendationEngine,
    RULE_LIBRARY,
    RemediationAction,
    MetricAlert,
    Severity,
    RiskLevel,
    RemediationStatus,
)


def test_seasonal_ewma_and_sustained_anomaly():
    detector = SustainedDeviationDetector(z_threshold=3.5, window_size=5, min_breach_count=3)
    source = "h_4af29c"
    metric = "cpu_pct"
    t0 = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)

    # 1. Warm up baseline around 40%
    for i in range(15):
        t = t0 + timedelta(seconds=i * 5)
        detector.ingest(source, metric, 40.0, t)

    # 2. Transient spike (1 window at 95%) should not be sustained
    t_spike = t0 + timedelta(seconds=80)
    res_spike = detector.ingest(source, metric, 95.0, t_spike)
    assert res_spike["is_transient"] is True
    assert res_spike["is_sustained"] is False

    # 3. Sustained spike (3 consecutive windows at 92%)
    alerts = []
    for w in range(1, 4):
        t_w = t0 + timedelta(seconds=85 + w * 5)
        res = detector.ingest(source, metric, 92.0, t_w)
        if res["is_sustained"]:
            alerts.append(res)

    assert len(alerts) >= 1
    assert alerts[-1]["severity"] in ["warning", "critical"]


def test_joint_multisignal_hstrees():
    hstrees = JointMultiSignalHSTrees(n_trees=10, height=6, window_size=50)

    # Ingest normal multi-signal vectors
    for _ in range(30):
        hstrees.learn_and_score({
            "cpu_pct": 35.0,
            "memory_pct": 45.0,
            "latency_ms": 25.0,
            "packet_loss_pct": 0.02,
        })

    # Normal sample gets low anomaly score
    score_normal = hstrees.learn_and_score({
        "cpu_pct": 36.0,
        "memory_pct": 46.0,
        "latency_ms": 26.0,
        "packet_loss_pct": 0.03,
    })
    assert score_normal < 0.65


def test_topology_graph_and_union_find_clustering():
    """Simulates Scenario 6: 9 alerts merged into 1 incident via 2-hop topology."""
    topo = TopologyGraph()
    # Topology: edge_switch -> api_gateway -> orders_db
    topo.add_component("edge_sw2", "switch")
    topo.add_component("api_gw", "gateway")
    topo.add_component("orders_db", "database")
    topo.add_dependency("edge_sw2", "api_gw")
    topo.add_dependency("api_gw", "orders_db")

    assert topo.get_hop_distance("edge_sw2", "orders_db") == 2
    assert topo.get_hop_distance("edge_sw2", "api_gw") == 1

    correlator = IncidentCorrelator(topology=topo, max_time_window_seconds=120, max_hop_distance=2)

    base_time = datetime(2026, 11, 20, 9, 14, 48, tzinfo=timezone.utc)

    # 9 alerts occurring across the 3 connected components within 2 minutes
    raw_alerts = [
        # edge_sw2 (root cause)
        MetricAlert(alert_id="a1", component_id="edge_sw2", metric_name="packet_loss_pct", severity=Severity.HIGH, observed_value=6.4, baseline_value=0.1, z_score=7.1, onset_time_utc=base_time),
        MetricAlert(alert_id="a2", component_id="edge_sw2", metric_name="latency_ms", severity=Severity.HIGH, observed_value=320.0, baseline_value=15.0, z_score=6.2, onset_time_utc=base_time + timedelta(seconds=2)),
        MetricAlert(alert_id="a3", component_id="edge_sw2", metric_name="crc_errors", severity=Severity.MEDIUM, observed_value=45.0, baseline_value=0.0, z_score=5.0, onset_time_utc=base_time + timedelta(seconds=4)),

        # api_gw (downstream hop 1)
        MetricAlert(alert_id="a4", component_id="api_gw", metric_name="latency_ms", severity=Severity.HIGH, observed_value=350.0, baseline_value=30.0, z_score=5.8, onset_time_utc=base_time + timedelta(seconds=7)),
        MetricAlert(alert_id="a5", component_id="api_gw", metric_name="error_rate_504", severity=Severity.HIGH, observed_value=12.0, baseline_value=0.1, z_score=6.5, onset_time_utc=base_time + timedelta(seconds=9)),
        MetricAlert(alert_id="a6", component_id="api_gw", metric_name="active_connections", severity=Severity.MEDIUM, observed_value=950.0, baseline_value=200.0, z_score=4.8, onset_time_utc=base_time + timedelta(seconds=11)),

        # orders_db (downstream hop 2)
        MetricAlert(alert_id="a7", component_id="orders_db", metric_name="query_timeouts", severity=Severity.HIGH, observed_value=28.0, baseline_value=0.0, z_score=6.1, onset_time_utc=base_time + timedelta(seconds=14)),
        MetricAlert(alert_id="a8", component_id="orders_db", metric_name="connection_pool_wait_ms", severity=Severity.MEDIUM, observed_value=410.0, baseline_value=20.0, z_score=4.9, onset_time_utc=base_time + timedelta(seconds=16)),
        MetricAlert(alert_id="a9", component_id="orders_db", metric_name="slow_queries_count", severity=Severity.MEDIUM, observed_value=19.0, baseline_value=1.0, z_score=4.2, onset_time_utc=base_time + timedelta(seconds=18)),
    ]

    for a in raw_alerts:
        correlator.ingest_alert(a)

    incidents = correlator.group_incidents()

    # All 9 alerts must be grouped into exactly 1 Incident!
    assert len(incidents) == 1
    inc = incidents[0]
    assert len(inc["affected_components"]) == 3
    assert set(inc["affected_components"]) == {"edge_sw2", "api_gw", "orders_db"}
    assert inc["raw_alerts_count"] == 9
    assert inc["noise_reduction"].noise_reduction_ratio_pct == 88.9


def test_cause_ranking_and_counterfactuals():
    topo = TopologyGraph()
    topo.add_component("edge_sw2", "switch")
    topo.add_component("api_gw", "gateway")
    topo.add_component("orders_db", "database")
    topo.add_dependency("edge_sw2", "api_gw")
    topo.add_dependency("api_gw", "orders_db")

    base_time = datetime(2026, 11, 20, 9, 14, 48, tzinfo=timezone.utc)

    alerts = [
        MetricAlert(alert_id="a1", component_id="edge_sw2", metric_name="packet_loss_pct", severity=Severity.HIGH, observed_value=6.4, baseline_value=0.1, z_score=7.1, onset_time_utc=base_time),
        MetricAlert(alert_id="a4", component_id="api_gw", metric_name="latency_ms", severity=Severity.HIGH, observed_value=350.0, baseline_value=30.0, z_score=5.8, onset_time_utc=base_time + timedelta(seconds=7)),
        MetricAlert(alert_id="a7", component_id="orders_db", metric_name="query_timeouts", severity=Severity.HIGH, observed_value=28.0, baseline_value=0.0, z_score=6.1, onset_time_utc=base_time + timedelta(seconds=14)),
    ]

    ranker = CauseRanker(topology=topo)
    likely_cause, alternatives, confidence = ranker.rank_causes(alerts, ["edge_sw2", "api_gw", "orders_db"])

    # edge_sw2 MUST be ranked as the root cause!
    assert likely_cause.component_id == "edge_sw2"
    assert confidence >= 0.75
    assert len(alternatives) == 2

    # Alternatives must contain elimination reasons
    alt_ids = [alt.candidate_id for alt in alternatives]
    assert "api_gw" in alt_ids
    assert "orders_db" in alt_ids


def test_recommendation_rules_and_evidence_card():
    engine = RecommendationEngine()
    assert len(RULE_LIBRARY) == 10

    topo = TopologyGraph()
    topo.add_component("edge_sw2", "switch")
    base_time = datetime(2026, 11, 20, 9, 14, 48, tzinfo=timezone.utc)

    alerts = [
        MetricAlert(alert_id="a1", component_id="edge_sw2", metric_name="packet_loss_pct", severity=Severity.HIGH, observed_value=6.4, baseline_value=0.1, z_score=7.1, onset_time_utc=base_time),
    ]

    action = engine.match_rule(alerts)
    assert action.runbook_id == "RBK-NET-FAILOVER-02"
    assert action.risk_level == RiskLevel.HIGH
    assert action.approvers_required == 2


def test_safe_remediation_lifecycle_and_rollback():
    action = RemediationAction(
        action_id="ACT-1001",
        incident_id="INC-0142",
        tenant_id="t_acme",
        target_component="edge_sw2",
        runbook_id="RBK-NET-FAILOVER-02",
        risk_level=RiskLevel.HIGH,
    )
    assert action.status == RemediationStatus.PROPOSED

    # 1. Policy check
    allowed = ["RBK-NET-FAILOVER-02", "RBK-SVC-SCALE-03"]
    passed = action.policy_check(allowed_runbooks=allowed, is_in_change_window=True)
    assert passed is True
    assert action.status == RemediationStatus.APPROVAL_PENDING

    # 2. Dual approval for high-risk action
    action.approve("admin_alice")
    assert action.status == RemediationStatus.APPROVAL_PENDING  # still needs 2nd
    action.approve("admin_bob")
    assert action.status == RemediationStatus.APPROVED

    # 3. Dry run
    dry_passed = action.dry_run(mock_system_precheck=True)
    assert dry_passed is True
    assert action.status == RemediationStatus.DRY_RUN_PASSED

    # 4. Execute simulation
    exec_passed = action.execute_simulation()
    assert exec_passed is True
    assert action.status == RemediationStatus.VERIFYING

    # 5. Verification fails -> automatic rollback!
    final_status = action.verify_and_close_or_rollback(metric_improved=False)
    assert final_status == RemediationStatus.ROLLED_BACK
    assert action.status == RemediationStatus.ROLLED_BACK

    # Audit log check
    steps = [entry["step"] for entry in action.audit_log]
    assert "PROPOSE" in steps
    assert "POLICY_CHECK" in steps
    assert "APPROVAL_COMPLETE" in steps
    assert "DRY_RUN" in steps
    assert "EXECUTE" in steps
    assert "ROLLBACK" in steps
