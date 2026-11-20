"""
Unit tests for VeilOps AIOps Phase 1 Baseline & Robust Z-Score Prototype
"""

import pytest
from datetime import datetime, timezone
from saas.aiops.baseline_prototype import SeasonalEWMABaseline, SustainedDeviationDetector


def test_hour_of_week_binning():
    dt_monday_noon = datetime(2026, 11, 16, 12, 0, 0, tzinfo=timezone.utc)  # Monday
    slot = SeasonalEWMABaseline.get_hour_of_week(dt_monday_noon)
    assert slot == 12  # 0 * 24 + 12

    dt_sunday_night = datetime(2026, 11, 22, 23, 0, 0, tzinfo=timezone.utc)  # Sunday
    slot_sunday = SeasonalEWMABaseline.get_hour_of_week(dt_sunday_night)
    assert slot_sunday == 6 * 24 + 23  # 167


def test_baseline_convergence_and_robust_z():
    baseline = SeasonalEWMABaseline(alpha=0.2, min_mad=1.0)
    source = "node_a"
    metric = "cpu_pct"
    t0 = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)

    # Ingest 15 samples around 50
    for i in range(15):
        t = datetime.fromtimestamp(t0.timestamp() + i * 5, tz=timezone.utc)
        baseline.update_and_score(source, metric, 50.0, t)

    # Sample equal to baseline should have z approx 0
    t_test = datetime.fromtimestamp(t0.timestamp() + 100, tz=timezone.utc)
    median, mad, z = baseline.update_and_score(source, metric, 50.0, t_test)
    assert abs(z) < 0.1
    assert abs(median - 50.0) < 0.5


def test_transient_spike_suppression():
    detector = SustainedDeviationDetector(z_threshold=3.5, window_size=5, min_breach_count=3)
    source = "node_b"
    metric = "latency_ms"
    t0 = datetime(2026, 11, 20, 14, 0, 0, tzinfo=timezone.utc)

    # 15 samples around 20 ms
    for i in range(15):
        t = datetime.fromtimestamp(t0.timestamp() + i * 5, tz=timezone.utc)
        detector.ingest_metric(source, metric, 20.0, t)

    # Inject 1 transient spike to 120 ms
    t_spike = datetime.fromtimestamp(t0.timestamp() + 80, tz=timezone.utc)
    res_spike = detector.ingest_metric(source, metric, 120.0, t_spike)

    assert res_spike.is_transient_spike is True
    assert res_spike.is_sustained_anomaly is False
    assert res_spike.severity == "info"

    # Immediately follow with normal values
    t_next = datetime.fromtimestamp(t0.timestamp() + 85, tz=timezone.utc)
    res_norm = detector.ingest_metric(source, metric, 20.0, t_next)
    assert res_norm.is_sustained_anomaly is False
    assert res_norm.severity == "normal"


def test_sustained_anomaly_detection():
    detector = SustainedDeviationDetector(z_threshold=3.5, window_size=5, min_breach_count=3)
    source = "switch_1"
    metric = "packet_loss_pct"
    t0 = datetime(2026, 11, 20, 8, 0, 0, tzinfo=timezone.utc)

    # Normal packet loss near 0.05%
    for i in range(15):
        t = datetime.fromtimestamp(t0.timestamp() + i * 5, tz=timezone.utc)
        detector.ingest_metric(source, metric, 0.05, t)

    # Inject sustained 8% packet loss across 4 consecutive windows
    alerts = []
    for w in range(1, 5):
        t_w = datetime.fromtimestamp(t0.timestamp() + 80 + w * 5, tz=timezone.utc)
        res = detector.ingest_metric(source, metric, 8.0, t_w)
        if res.is_sustained_anomaly:
            alerts.append(res)

    # By the 3rd breach, sustained anomaly must be triggered!
    assert len(alerts) >= 2
    assert alerts[0].severity in ["warning", "critical"]
    assert "Sustained deviation" in alerts[0].reason
