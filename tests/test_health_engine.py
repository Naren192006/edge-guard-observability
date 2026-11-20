import pytest
from datetime import datetime, timezone, timedelta
from saas.workers.health_engine import CollectorHealthEngine, HealthState


def test_health_engine_nominal_state():
    engine = CollectorHealthEngine()
    now = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    
    state, reasons, transition = engine.evaluate_health("t_acme", "c_blr_dc1", now)
    assert state == HealthState.EXCELLENT
    assert "NOMINAL" in reasons


def test_heartbeat_staleness_downgrades():
    engine = CollectorHealthEngine()
    t0 = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    engine.record_heartbeat("t_acme", "c_blr_dc1", t0)
    
    # 1. Check at 16s silence -> FAIR with STALE_DATA
    t_16s = t0 + timedelta(seconds=16)
    state, reasons, transition = engine.evaluate_health("t_acme", "c_blr_dc1", t_16s)
    assert state == HealthState.FAIR
    assert "STALE_DATA" in reasons
    assert transition is not None
    assert transition.old_state == HealthState.EXCELLENT
    assert transition.new_state == HealthState.FAIR

    # 2. Check at 61s silence -> POOR with COLLECTOR_OFFLINE
    t_61s = t0 + timedelta(seconds=61)
    state, reasons, transition = engine.evaluate_health("t_acme", "c_blr_dc1", t_61s)
    assert state == HealthState.POOR
    assert "COLLECTOR_OFFLINE" in reasons
    assert transition is not None
    assert transition.new_state == HealthState.POOR


def test_hysteresis_anti_flapping():
    engine = CollectorHealthEngine(hysteresis_required_windows=3)
    t0 = datetime(2026, 11, 20, 10, 0, 0, tzinfo=timezone.utc)
    engine.record_heartbeat("t_acme", "c_blr_dc1", t0)

    # 1. Immediate downgrade on high packet loss (6%) -> POOR
    state, reasons, transition = engine.evaluate_health(
        "t_acme", "c_blr_dc1", t0, metrics={"packet_loss_pct": 6.0}
    )
    assert state == HealthState.POOR
    assert "PACKET_LOSS_ELEVATED" in reasons

    # 2. Window 1 of healthy metrics -> MUST REMAIN POOR due to hysteresis
    t1 = t0 + timedelta(seconds=5)
    engine.record_heartbeat("t_acme", "c_blr_dc1", t1)
    state, reasons, transition = engine.evaluate_health(
        "t_acme", "c_blr_dc1", t1, metrics={"packet_loss_pct": 0.0}
    )
    assert state == HealthState.POOR
    assert transition is None

    # 3. Window 2 of healthy metrics -> MUST REMAIN POOR
    t2 = t0 + timedelta(seconds=10)
    engine.record_heartbeat("t_acme", "c_blr_dc1", t2)
    state, reasons, transition = engine.evaluate_health(
        "t_acme", "c_blr_dc1", t2, metrics={"packet_loss_pct": 0.0}
    )
    assert state == HealthState.POOR
    assert transition is None

    # 4. Window 3 of healthy metrics -> RECOVERS TO EXCELLENT
    t3 = t0 + timedelta(seconds=15)
    engine.record_heartbeat("t_acme", "c_blr_dc1", t3)
    state, reasons, transition = engine.evaluate_health(
        "t_acme", "c_blr_dc1", t3, metrics={"packet_loss_pct": 0.0}
    )
    assert state == HealthState.EXCELLENT
    assert transition is not None
    assert transition.old_state == HealthState.POOR
    assert transition.new_state == HealthState.EXCELLENT
    assert "NOMINAL" in reasons
