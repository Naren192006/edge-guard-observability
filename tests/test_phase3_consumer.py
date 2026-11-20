"""
Unit tests for VeilOps Phase 3 AIOps Streaming Engine & Consumer
"""

from datetime import datetime, timezone, timedelta
import pytest

from saas.aiops.consumer import AIOpsEngine
from saas.aiops.schemas import Severity, RiskLevel, RemediationStatus


def test_cpu_deviation_with_contributing_signals():
    """Validates: A CPU deviation is flagged with contributing signals within 15 seconds."""
    engine = AIOpsEngine()
    source = "h_4af29c"
    base_time = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)

    # 1. Warm up baseline around 40% CPU
    for i in range(15):
        t = base_time + timedelta(seconds=i * 5)
        payload = {
            "tenant_id": "t_acme",
            "collector_id": "c_blr_dc1",
            "event_time_utc": t.isoformat(),
            "metrics": [{"src": source, "name": "cpu_pct", "mean": 40.0, "p95": 40.0}],
        }
        engine.process_payload(payload)

    # 2. Inject sustained CPU deviation to 94% across 3 windows
    cards = []
    for w in range(1, 4):
        t_spike = base_time + timedelta(seconds=80 + w * 5)
        payload_spike = {
            "tenant_id": "t_acme",
            "collector_id": "c_blr_dc1",
            "event_time_utc": t_spike.isoformat(),
            "metrics": [{"src": source, "name": "cpu_pct", "mean": 94.0, "p95": 94.0}],
        }
        res = engine.process_payload(payload_spike)
        if res:
            cards.extend(res)

    # Must produce Evidence Card with contributing signals
    assert len(cards) >= 1
    card = cards[-1]
    assert card.likely_cause.component_id == source
    assert len(card.contributing_signals) >= 1
    sig = card.contributing_signals[0]
    assert sig.metric_or_pattern == "cpu_pct"
    assert sig.observed_value == 94.0
    assert sig.z_score > 3.5
    assert card.suggested_action.runbook_id == "RBK-SVC-SCALE-03"


def test_cascade_scenario_nine_alerts_to_one_incident():
    """Validates: The cascade scenario produces one incident from nine alerts."""
    engine = AIOpsEngine()
    base_time = datetime(2026, 11, 20, 9, 14, 48, tzinfo=timezone.utc)

    # Pre-warm baselines so sudden breaches are clear anomalies
    for _ in range(10):
        engine.detector.ingest("edge_sw2", "packet_loss_pct", 0.05, base_time)
        engine.detector.ingest("edge_sw2", "latency_ms", 15.0, base_time)
        engine.detector.ingest("api_gw", "latency_ms", 30.0, base_time)

    # Deliver 9 alerts across 3 connected components within 2 minutes
    payload_cascade = {
        "tenant_id": "t_acme",
        "collector_id": "c_blr_dc1",
        "event_time_utc": base_time.isoformat(),
        "metrics": [
            # edge_sw2 breaches (onset 09:14:48Z)
            {"src": "edge_sw2", "name": "packet_loss_pct", "mean": 6.4, "p95": 6.4},
            {"src": "edge_sw2", "name": "latency_ms", "mean": 320.0, "p95": 320.0},
            {"src": "edge_sw2", "name": "packet_loss_pct", "mean": 6.5, "p95": 6.5},
            # api_gw breaches (onset 09:14:55Z)
            {"src": "api_gw", "name": "latency_ms", "mean": 350.0, "p95": 350.0},
            {"src": "api_gw", "name": "latency_ms", "mean": 360.0, "p95": 360.0},
            # orders_db breaches (onset 09:15:02Z)
            {"src": "orders_db", "name": "db_connections_active", "mean": 96.0, "p95": 96.0},
            {"src": "orders_db", "name": "db_connections_active", "mean": 98.0, "p95": 98.0},
        ],
        "security": [
            {"src": "p_77d1", "cat": "auth_fail", "count": 45, "risk": "high"},
            {"src": "p_77d1", "cat": "auth_fail", "count": 48, "risk": "high"},
        ],
    }

    # Simulate 3 windows so sustained condition is met
    cards = []
    for step in range(3):
        t_step = base_time + timedelta(seconds=step * 5)
        payload_cascade["event_time_utc"] = t_step.isoformat()
        cards = engine.process_payload(payload_cascade)

    # 1. Exactly 1 incident created
    assert len(cards) == 1
    card = cards[0]

    # 2. edge_sw2 identified as root cause
    assert card.likely_cause.component_id == "edge_sw2"
    assert card.confidence >= 0.60

    # 3. High risk action needs 2 approvers
    assert card.suggested_action.runbook_id == "RBK-NET-FAILOVER-02"
    assert card.suggested_action.risk_level == RiskLevel.HIGH
    assert card.suggested_action.approvers_required == 2

    # 4. Check noise reduction
    stats = engine.get_noise_reduction_stats()
    assert stats["raw_alerts"] >= 9
    assert stats["incidents"] == 1
    assert stats["reduction_ratio_pct"] >= 80.0
