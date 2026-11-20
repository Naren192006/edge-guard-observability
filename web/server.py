"""
VeilOps Phase 3 Web Server & AIOps API
Serves the interactive Evidence Console and REST APIs for incidents and scenarios.
"""

import os
from datetime import datetime, timezone
from typing import Dict, Any
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from saas.aiops.consumer import AIOpsEngine
from saas.aiops.schemas import MetricAlert, Severity

app = FastAPI(title="VeilOps AIOps Evidence Console")
engine = AIOpsEngine()


@app.on_event("startup")
def preload_demo_incidents():
    """Initializes with canonical Scenario 6 (9 alerts -> 1 incident) on boot."""
    base_time = datetime.now(timezone.utc)
    demo_payload = {
        "payload_id": "01JD8Z3K7Q9X4M2V6T1B5N8R0C",
        "tenant_id": "t_acme",
        "collector_id": "c_blr_dc1",
        "event_time_utc": base_time.isoformat(),
        "metrics": [
            {"src": "edge_sw2", "name": "packet_loss_pct", "mean": 6.4, "p95": 6.4},
            {"src": "edge_sw2", "name": "latency_ms", "mean": 320.0, "p95": 320.0},
            {"src": "api_gw", "name": "latency_ms", "mean": 350.0, "p95": 350.0},
            {"src": "orders_db", "name": "db_connections_active", "mean": 96.0, "p95": 96.0},
        ],
        "security": [
            {"src": "p_77d1", "cat": "auth_fail", "count": 48, "risk": "high"}
        ]
    }
    # Pre-warm baseline
    for _ in range(5):
        engine.detector.ingest("edge_sw2", "packet_loss_pct", 0.05, base_time)
        engine.detector.ingest("edge_sw2", "latency_ms", 15.0, base_time)
    
    # Process payload
    engine.process_payload(demo_payload)


@app.get("/", response_class=HTMLResponse)
def get_dashboard():
    html_path = os.path.join(os.path.dirname(__file__), "index.html")
    with open(html_path, "r", encoding="utf-8") as f:
        return HTMLResponse(content=f.read())


@app.get("/api/incidents")
def get_incidents():
    cards = list(engine.active_evidence_cards.values())
    stats = engine.get_noise_reduction_stats()
    return JSONResponse(content={
        "incidents": [c.model_dump(mode="json") for c in cards],
        "noise_reduction": stats,
    })


@app.get("/api/incidents/{incident_id}/evidence")
def get_evidence_card(incident_id: str):
    if incident_id not in engine.active_evidence_cards:
        raise HTTPException(status_code=404, detail="Incident not found")
    return JSONResponse(content=engine.active_evidence_cards[incident_id].model_dump(mode="json"))


@app.post("/api/remediation/{action_id}/approve")
def approve_remediation(action_id: str, approver_id: str = "admin_alice"):
    action = None
    for a in engine.remediation_actions.values():
        if a.action_id == action_id:
            action = a
            break
    if not action:
        raise HTTPException(status_code=404, detail="Remediation action not found")

    action.approve(approver_id)
    if action.status.value == "approved":
        action.dry_run()
        action.execute_simulation()
        action.verify_and_close_or_rollback(metric_improved=True)

    return JSONResponse(content={"action_id": action.action_id, "status": action.status.value, "audit": action.audit_log})


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("web.server:app", host="0.0.0.0", port=8082, reload=True)
