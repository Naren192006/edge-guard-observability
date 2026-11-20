"""
VeilOps AIOps Phase 2 - Safe Remediation State Machine

Lifecycle:
PROPOSE -> POLICY_CHECK -> APPROVAL -> DRY_RUN -> EXECUTE -> VERIFY -> (COMPLETED | ROLLBACK) -> AUDIT

Key Safeguard:
The SaaS NEVER holds infrastructure credentials. It emits only cryptographically
signed action IDs. Local collector executes with local credentials.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from .schemas import RiskLevel, RemediationStatus


class RemediationAction:
    """Represents a discrete remediation action undergoing closed-loop verification."""

    def __init__(
        self,
        action_id: str,
        incident_id: str,
        tenant_id: str,
        target_component: str,
        runbook_id: str,
        risk_level: RiskLevel,
    ):
        self.action_id = action_id
        self.incident_id = incident_id
        self.tenant_id = tenant_id
        self.target_component = target_component
        self.runbook_id = runbook_id
        self.risk_level = risk_level

        self.status: RemediationStatus = RemediationStatus.PROPOSED
        self.approvals: List[str] = []
        self.required_approvals: int = 2 if risk_level == RiskLevel.HIGH else 1
        self.before_state_snapshot: Dict[str, Any] = {}
        self.audit_log: List[Dict[str, Any]] = []

        self._record_audit("PROPOSE", {"status": "created", "runbook": runbook_id})

    def _record_audit(self, step: str, details: Dict[str, Any]):
        entry = {
            "timestamp_utc": datetime.now(timezone.utc).isoformat(),
            "action_id": self.action_id,
            "step": step,
            "status": self.status.value,
            "details": details,
        }
        self.audit_log.append(entry)

    def policy_check(self, allowed_runbooks: List[str], is_in_change_window: bool) -> bool:
        """Step 2: Policy check against tenant allowed runbooks and change windows."""
        if not is_in_change_window:
            self.status = RemediationStatus.REJECTED
            self._record_audit("POLICY_CHECK", {"passed": False, "reason": "Outside maintenance change window"})
            return False

        if self.runbook_id not in allowed_runbooks:
            self.status = RemediationStatus.REJECTED
            self._record_audit("POLICY_CHECK", {"passed": False, "reason": "Runbook not permitted by tenant policy"})
            return False

        self.status = RemediationStatus.POLICY_CHECKED
        self._record_audit("POLICY_CHECK", {"passed": True})
        self.status = RemediationStatus.APPROVAL_PENDING
        return True

    def approve(self, approver_id: str) -> bool:
        """Step 3: Human-in-the-loop approval. High-risk requires 2 approvals."""
        if self.status != RemediationStatus.APPROVAL_PENDING:
            return False

        if approver_id not in self.approvals:
            self.approvals.append(approver_id)
            self._record_audit("APPROVE", {"approver": approver_id, "count": len(self.approvals)})

        if len(self.approvals) >= self.required_approvals:
            self.status = RemediationStatus.APPROVED
            self._record_audit("APPROVAL_COMPLETE", {"approvers": self.approvals})
            return True

        return False

    def dry_run(self, mock_system_precheck: bool = True) -> bool:
        """Step 4: Local collector sandbox dry-run pre-checks."""
        if self.status != RemediationStatus.APPROVED:
            return False

        if not mock_system_precheck:
            self.status = RemediationStatus.REJECTED
            self._record_audit("DRY_RUN", {"passed": False, "reason": "Pre-check failed in sandbox"})
            return False

        # Capture pre-state snapshot
        self.before_state_snapshot = {
            "target": self.target_component,
            "captured_at": datetime.now(timezone.utc).isoformat(),
            "active_route": "primary_uplink",
        }
        self.status = RemediationStatus.DRY_RUN_PASSED
        self._record_audit("DRY_RUN", {"passed": True, "snapshot": self.before_state_snapshot})
        return True

    def execute_simulation(self) -> bool:
        """Step 5: Apply change on mock target."""
        if self.status != RemediationStatus.DRY_RUN_PASSED:
            return False

        self.status = RemediationStatus.EXECUTING
        self._record_audit("EXECUTE", {"action": "failover_to_secondary", "simulated": True})
        self.status = RemediationStatus.VERIFYING
        return True

    def verify_and_close_or_rollback(self, metric_improved: bool) -> RemediationStatus:
        """
        Step 6 & 7: 2-minute verification watch.
        If metrics improve -> COMPLETED.
        If metrics worsen -> AUTOMATIC ROLLBACK restoring before-state snapshot.
        """
        if self.status != RemediationStatus.VERIFYING:
            return self.status

        if metric_improved:
            self.status = RemediationStatus.COMPLETED
            self._record_audit("VERIFY", {"result": "success", "metrics_recovered": True})
        else:
            # Trigger automatic rollback
            self.status = RemediationStatus.ROLLED_BACK
            self._record_audit("ROLLBACK", {
                "result": "metric_deteriorated",
                "restored_snapshot": self.before_state_snapshot,
                "reason": "Target metric failed to recover within 2 minutes.",
            })

        return self.status
