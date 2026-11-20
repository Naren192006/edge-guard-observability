"""
VeilOps Phase 3 Unit Tests
Synchronous test wrappers with asyncio.run() - runs reliably in any environment.
"""

import os
import json
import asyncio
from datetime import datetime, timezone
import pytest

from saas.api.main import (
    app,
    ingest_telemetry,
    get_tenant_metrics,
    get_collector_fleet,
    get_latency_stats,
    get_reconciliation_proof,
    serve_dashboard,
    _PROCESSED_PAYLOADS,
    _COLLECTOR_HEALTH,
    SEEDED_TENANTS
)

SAMPLE_PATH = os.path.join(os.path.dirname(__file__), "../contracts/samples/valid_payload_1.json")
with open(SAMPLE_PATH, "r", encoding="utf-8") as f:
    SAMPLE_PAYLOAD = json.load(f)


def test_dashboard_serving_html():
    res = asyncio.run(serve_dashboard())
    assert res.status_code == 200
    html = res.body.decode("utf-8")
    assert "VeilOps Tier 2 SaaS Platform" in html
    assert "tenantSelect" in html
    assert "Row-Level Security" in html


def test_ingest_and_idempotency_deduplication():
    # 1. Ingest first time -> Expect duplicate = False
    payload = dict(SAMPLE_PAYLOAD)
    payload["payload_id"] = "01JD8Z3K7Q9X4M2V6T1B5N8RA1"
    payload["seq"] = 500

    resp1 = asyncio.run(ingest_telemetry(payload=payload))
    body1 = json.loads(resp1.body.decode("utf-8"))
    assert resp1.status_code == 200
    assert body1["status"] == "ACK"
    assert body1["duplicate"] is False

    # 2. Ingest duplicate -> Expect duplicate = True (idempotent ACK)
    resp2 = asyncio.run(ingest_telemetry(payload=payload))
    body2 = json.loads(resp2.body.decode("utf-8"))
    assert resp2.status_code == 200
    assert body2["status"] == "ACK"
    assert body2["duplicate"] is True


def test_replaying_duplicates_and_shuffled_order():
    """
    Requirement 7: replaying duplicates and shuffled order leaves charts and counts unchanged.
    """
    tenant_id = "t_acme"
    rec_before = asyncio.run(get_reconciliation_proof(tenant_id=tenant_id, collector_id="c_blr_dc1"))
    count_before = rec_before["unique_payload_ids"]

    # Generate 3 distinct payloads
    p1 = dict(SAMPLE_PAYLOAD); p1["payload_id"] = "01JD8Z3K7Q9X4M2V6T1B5N8RB1"; p1["seq"] = 501
    p2 = dict(SAMPLE_PAYLOAD); p2["payload_id"] = "01JD8Z3K7Q9X4M2V6T1B5N8RB2"; p2["seq"] = 502
    p3 = dict(SAMPLE_PAYLOAD); p3["payload_id"] = "01JD8Z3K7Q9X4M2V6T1B5N8RB3"; p3["seq"] = 503

    # Ingest shuffled order: [p3, p1, p2]
    asyncio.run(ingest_telemetry(payload=p3))
    asyncio.run(ingest_telemetry(payload=p1))
    asyncio.run(ingest_telemetry(payload=p2))

    # Ingest duplicates of all 3
    for p in [p1, p2, p3]:
        dup_resp = asyncio.run(ingest_telemetry(payload=p))
        dup_body = json.loads(dup_resp.body.decode("utf-8"))
        assert dup_body["duplicate"] is True

    # Reconcile count: Exactly 3 unique payloads added, zero loss, duplicates ignored
    rec_after = asyncio.run(get_reconciliation_proof(tenant_id=tenant_id, collector_id="c_blr_dc1"))
    assert rec_after["unique_payload_ids"] == count_before + 3
    assert rec_after["status"] == "VERIFIED_ZERO_LOSS_ZERO_DUPLICATES"


def test_row_level_security_tenant_isolation():
    """
    Requirement 3: Row-Level Security so tenant B can never read tenant A.
    """
    # Query as Tenant A (t_acme)
    res_a = asyncio.run(get_tenant_metrics(tenant_id="t_acme"))
    assert res_a["tenant_id"] == "t_acme"
    assert res_a["count"] >= 1

    # Query as Tenant B (t_globex)
    res_b = asyncio.run(get_tenant_metrics(tenant_id="t_globex"))
    assert res_b["tenant_id"] == "t_globex"
    assert res_b["count"] == 0  # Zero rows from Tenant A returned


def test_latency_panel_target():
    """
    Requirement 6: Latency panel p50/p95/p99 and target <= 10s.
    """
    stats = asyncio.run(get_latency_stats())
    assert stats["target_met_p95"] is True
    assert stats["p95_seconds"] <= 10.0


def test_certificate_binding_mismatch():
    """
    Requirement 2: Tenant binding check against certificate SAN.
    """
    payload = dict(SAMPLE_PAYLOAD)
    payload["payload_id"] = "01JD8Z3K7Q9X4M2V6T1B5N8RC9"
    payload["tenant_id"] = "t_acme"

    with pytest.raises(Exception) as exc:
        asyncio.run(ingest_telemetry(payload=payload, x_client_cert_san="t_globex"))
    assert "Certificate SAN mismatch" in str(exc.value)
