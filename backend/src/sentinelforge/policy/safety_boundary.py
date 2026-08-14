from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from sentinelforge.domain.action_ir import ActionIR
from sentinelforge.domain.experiment import (
    AdversarialScenario,
    ExperimentConstraints,
    PolicyDecision,
    PolicyDecisionStatus,
    RiskLevel,
)
from sentinelforge.domain.exceptions import SecurityRejection, SecurityRejectionCode
from sentinelforge.policy.engine import PolicyEngine

RISK_ORDER = {
    RiskLevel.LOW: 1,
    RiskLevel.MEDIUM: 2,
    RiskLevel.HIGH: 3,
    RiskLevel.CRITICAL: 4,
}


class ExperimentSafetyBoundary:
    """High-level safety & authorization boundary for SentinelForge experiments.

    Reframes the Policy Engine from a static attack allowlist into an
    authorization boundary that evaluates:
      - Authorized targets & user identities
      - Experiment risk level vs maximum permitted risk
      - Mandatory approval requirements
      - Low-level action execution invariants (via PolicyEngine)
    """

    def __init__(self, constraints: Optional[ExperimentConstraints] = None):
        self.constraints = constraints or ExperimentConstraints()

    def record_decision(self, db_session, decision: PolicyDecision):
        """Persist a PolicyDecision as a PolicyDecisionRecord in the database."""
        if db_session is None:
            return None
        from sentinelforge.db.models import PolicyDecisionRecord
        rec = PolicyDecisionRecord(
            id=decision.decision_id,
            organization_id=decision.organization_id,
            scenario_id=decision.scenario_id,
            blueprint_id=decision.blueprint_id,
            status=decision.status.value if hasattr(decision.status, "value") else str(decision.status),
            reason=decision.reason,
            evaluated_at=decision.evaluated_at,
        )
        db_session.add(rec)
        db_session.commit()
        return rec

    def evaluate_scenario(
        self, scenario: AdversarialScenario, is_human_approved: bool = False, db_session=None
    ) -> PolicyDecision:
        """Evaluate an AdversarialScenario before an ExecutionPlan is generated."""
        proposed_risk = RISK_ORDER.get(scenario.proposed_risk_level, 2)
        max_permitted_risk = RISK_ORDER.get(self.constraints.max_risk_level, 3)

        if proposed_risk > max_permitted_risk:
            decision = PolicyDecision(
                organization_id=scenario.organization_id,
                scenario_id=scenario.scenario_id,
                status=PolicyDecisionStatus.DENIED,
                reason=(
                    f"Scenario risk level {scenario.proposed_risk_level.value} exceeds "
                    f"maximum permitted risk {self.constraints.max_risk_level.value}"
                ),
            )
        elif self.constraints.requires_human_approval and not is_human_approved:
            decision = PolicyDecision(
                organization_id=scenario.organization_id,
                scenario_id=scenario.scenario_id,
                status=PolicyDecisionStatus.ESCALATED,
                reason="Scenario requires human approval prior to execution plan generation",
            )
        else:
            decision = PolicyDecision(
                organization_id=scenario.organization_id,
                scenario_id=scenario.scenario_id,
                status=PolicyDecisionStatus.ALLOWED,
                reason="Scenario authorized by Experiment Safety Boundary",
            )

        if db_session:
            self.record_decision(db_session, decision)
        return decision

    def evaluate_action_ir(
        self, action: ActionIR, org_id: UUID, current_time: Optional[datetime] = None, db_session=None
    ) -> PolicyDecision:
        """Evaluate an ActionIR against high-level constraints and low-level policy invariants."""
        # 1. Target check against constraints
        if action.target not in self.constraints.allowed_targets:
            decision = PolicyDecision(
                organization_id=org_id,
                blueprint_id=action.blueprint_id,
                status=PolicyDecisionStatus.DENIED,
                reason=f"Target '{action.target}' is not in authorized targets list {self.constraints.allowed_targets}",
            )
        # 2. User check against constraints
        elif action.run_as_user not in self.constraints.allowed_users:
            decision = PolicyDecision(
                organization_id=org_id,
                blueprint_id=action.blueprint_id,
                status=PolicyDecisionStatus.DENIED,
                reason=f"User '{action.run_as_user}' is not in authorized users list {self.constraints.allowed_users}",
            )
        else:
            # 3. Delegated low-level PolicyEngine validation
            try:
                PolicyEngine.validate(action, current_time=current_time)
                decision = PolicyDecision(
                    organization_id=org_id,
                    blueprint_id=action.blueprint_id,
                    status=PolicyDecisionStatus.ALLOWED,
                    reason="ActionIR authorized by Experiment Safety Boundary and Policy Engine",
                )
            except SecurityRejection as exc:
                decision = PolicyDecision(
                    organization_id=org_id,
                    blueprint_id=action.blueprint_id,
                    status=PolicyDecisionStatus.DENIED,
                    reason=f"Low-level policy invariant violation: {exc.message} [{exc.code.value}]",
                )

        if db_session:
            self.record_decision(db_session, decision)
        return decision
