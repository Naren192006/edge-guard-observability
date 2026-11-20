"""
VeilOps AIOps Phase 2 - Schemas & Data Contracts
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class HealthState(str, Enum):
    EXCELLENT = "excellent"
    GOOD = "good"
    FAIR = "fair"
    POOR = "poor"


class NodeType(str, Enum):
    HOST = "host"
    SWITCH = "switch"
    DATABASE = "database"
    SERVICE = "service"
    GATEWAY = "gateway"


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RemediationStatus(str, Enum):
    PROPOSED = "proposed"
    POLICY_CHECKED = "policy_checked"
    APPROVAL_PENDING = "approval_pending"
    APPROVED = "approved"
    DRY_RUN_PASSED = "dry_run_passed"
    EXECUTING = "executing"
    VERIFYING = "verifying"
    COMPLETED = "completed"
    ROLLED_BACK = "rolled_back"
    REJECTED = "rejected"


class TopologyNode(BaseModel):
    id: str
    name: str
    type: NodeType
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TopologyEdge(BaseModel):
    source: str
    target: str
    relationship: str = "depends_on"
    latency_weight_ms: float = 1.0


class MetricAlert(BaseModel):
    alert_id: str
    component_id: str
    metric_name: str
    severity: Severity
    observed_value: float
    baseline_value: float
    z_score: float
    onset_time_utc: datetime
    template_hash: Optional[str] = None
    category: str = "metric_anomaly"

    @property
    def dedupe_key(self) -> str:
        return f"{self.component_id}:{self.metric_name}:{self.severity.value}"


class ContributingSignal(BaseModel):
    source: str
    metric_or_pattern: str
    observed_value: float
    baseline_value: float
    z_score: float
    onset_time_utc: datetime


class LikelyCause(BaseModel):
    component_id: str
    confidence_score: float = Field(ge=0.0, le=1.0)
    reasoning: str


class AlternativeElimination(BaseModel):
    candidate_id: str
    elimination_reason: str


class SuggestedAction(BaseModel):
    runbook_id: str
    description: str
    risk_level: RiskLevel
    requires_approval: bool = True
    approvers_required: int = 1
    automated_safe_simulation: bool = True


class NoiseReductionMetric(BaseModel):
    raw_alerts_merged: int
    incidents_created: int
    noise_reduction_ratio_pct: float


class EvidenceCard(BaseModel):
    incident_id: str
    severity: Severity
    opened_at_utc: datetime
    affected_components: List[str]
    likely_cause: LikelyCause
    confidence: float = Field(ge=0.0, le=1.0)
    contributing_signals: List[ContributingSignal]
    why_this_cause: str
    why_not_alternatives: List[AlternativeElimination]
    suggested_action: SuggestedAction
    noise_reduction: Optional[NoiseReductionMetric] = None


class RecommendationRule(BaseModel):
    rule_id: str
    pattern_description: str
    target_metric: str
    threshold_condition: str
    runbook_id: str
    action_description: str
    risk_level: RiskLevel
    approvers_needed: int
