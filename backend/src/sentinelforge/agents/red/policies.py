"""SafetyBoundaryBridge — deterministic gate between LLM proposals and execution.

SECURITY ROLE:
This is the SINGLE mandatory gate between Tier 1 (LLM proposals) and Tier 2
(signed, executable blueprints). A proposal becomes executable ONLY when:

  1. The AdversarialScenario passes ExperimentSafetyBoundary.evaluate_scenario.
  2. EVERY ActionIR passes ExperimentSafetyBoundary.evaluate_action_ir, which
     delegates to PolicyEngine for exact executable + argument allowlists.
  3. ALL actions pass before ANY SignedBlueprint is produced.

If any action is denied, NO blueprints are signed (fail-closed, atomic).
"""

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional
from uuid import UUID, uuid4

from sentinelforge.agents.red.schemas import ScenarioProposalSpec
from sentinelforge.domain.action_ir import ActionIR, ActionType
from sentinelforge.domain.blueprint import SignedBlueprint
from sentinelforge.domain.experiment import (
    AdversarialScenario,
    ExperimentConstraints,
    PolicyDecision,
    PolicyDecisionStatus,
    SecurityObjective,
)
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary
from sentinelforge.policy.signing import BlueprintSigner

logger = logging.getLogger(__name__)

# Default validity window for generated blueprints.
BLUEPRINT_VALIDITY_SECONDS = 30


def _resolve_signing_key(
    signing_key: Optional[str] = None,
    signer: Optional[BlueprintSigner] = None,
) -> str:
    """Resolve the signing key from explicit argument, signer, or environment.

    Priority:
      1. Explicit signing_key argument
      2. Key extracted from an existing signer instance
      3. SENTINELFORGE_SIGNING_KEY environment variable

    Raises:
        ProviderConfigurationError: If no signing key can be resolved.
    """
    if signing_key is not None:
        return signing_key
    if signer is not None:
        # Extract key from existing signer (encoded bytes -> str)
        return signer.key.decode("utf-8") if isinstance(signer.key, bytes) else signer.key
    env_key = os.environ.get("SENTINELFORGE_SIGNING_KEY")
    if env_key:
        return env_key
    raise ValueError(
        "Signing key is required. Provide signing_key, a signer instance, "
        "or set the SENTINELFORGE_SIGNING_KEY environment variable."
    )


@dataclass
class SafetyBridgeResult:
    """Outcome of evaluating an LLM scenario proposal through the safety gate."""

    scenario: Optional[AdversarialScenario] = None
    actions: List[ActionIR] = field(default_factory=list)
    policy_decision: Optional[PolicyDecision] = None
    signed_blueprints: List[SignedBlueprint] = field(default_factory=list)

    @property
    def is_allowed(self) -> bool:
        return (
            self.policy_decision is not None
            and self.policy_decision.status == PolicyDecisionStatus.ALLOWED
        )

    @property
    def is_denied(self) -> bool:
        return (
            self.policy_decision is not None
            and self.policy_decision.status == PolicyDecisionStatus.DENIED
        )


class SafetyBoundaryBridge:
    """Converts ScenarioProposalSpec into validated ActionIR + SignedBlueprint.

    The bridge NEVER signs anything that has not passed the deterministic
    ExperimentSafetyBoundary / PolicyEngine checks. It is the authority for
    the exact same allowlists used by the existing RedAgentPlanner.
    """

    def __init__(
        self,
        signer: Optional[BlueprintSigner] = None,
        safety_boundary: Optional[ExperimentSafetyBoundary] = None,
        constraints: Optional[ExperimentConstraints] = None,
        signing_key: Optional[str] = None,
        key_id: str = "key1",
    ):
        resolved_key = _resolve_signing_key(signing_key=signing_key, signer=signer)
        self.signer = signer or BlueprintSigner(key=resolved_key, key_id=key_id)
        if safety_boundary is not None:
            self.boundary = safety_boundary
        else:
            self.boundary = ExperimentSafetyBoundary(constraints)

    def evaluate_proposal(
        self,
        objective: SecurityObjective,
        proposal: ScenarioProposalSpec,
        is_human_approved: bool = False,
        current_time: Optional[datetime] = None,
    ) -> SafetyBridgeResult:
        """Evaluate a full scenario proposal; sign ONLY if everything is ALLOWED.

        Args:
            objective: The tenant-scoped SecurityObjective driving this proposal.
            proposal: LLM-proposed scenario (untrusted input).
            is_human_approved: Human approval override for high-risk scenarios.
            current_time: Overridable clock (used by tests for expiry semantics).

        Returns:
            SafetyBridgeResult with the policy decision and (possibly empty)
            list of signed blueprints.
        """
        now = current_time or datetime.now(timezone.utc)
        org_id = objective.organization_id

        # 1. Build AdversarialScenario from the proposal.
        scenario = AdversarialScenario(
            scenario_id=uuid4(),
            objective_id=objective.objective_id,
            organization_id=org_id,
            title=proposal.title,
            strategy_description=proposal.strategy_description,
            technique_ids=proposal.technique_ids,
            proposed_risk_level=proposal.proposed_risk_level,
            created_by="red_agent_llm",
        )

        # 2. Evaluate scenario-level risk / approval.
        scenario_decision = self.boundary.evaluate_scenario(
            scenario, is_human_approved=is_human_approved
        )
        if scenario_decision.status != PolicyDecisionStatus.ALLOWED:
            return SafetyBridgeResult(
                scenario=scenario,
                actions=[],
                policy_decision=scenario_decision,
                signed_blueprints=[],
            )

        # 3. Convert proposed actions to bounded ActionIR candidates.
        candidate_actions: List[ActionIR] = []
        for spec in proposal.proposed_actions:
            candidate_actions.append(
                self._to_action_ir(
                    spec=spec,
                    technique_id=spec.technique_id,
                    now=now,
                )
            )

        # 4. Evaluate EVERY action through ExperimentSafetyBoundary + PolicyEngine.
        for action in candidate_actions:
            action_decision = self.boundary.evaluate_action_ir(
                action, org_id=org_id, current_time=now
            )
            if action_decision.status != PolicyDecisionStatus.ALLOWED:
                # Fail-closed: if ANY action fails, none are signed.
                return SafetyBridgeResult(
                    scenario=scenario,
                    actions=candidate_actions,
                    policy_decision=action_decision,
                    signed_blueprints=[],
                )

        # 5. All actions ALLOWED -> sign every blueprint.
        signed = [self.signer.sign(**self._sign_kwargs(action)) for action in candidate_actions]

        return SafetyBridgeResult(
            scenario=scenario,
            actions=candidate_actions,
            policy_decision=scenario_decision,
            signed_blueprints=signed,
        )

    def _to_action_ir(
        self,
        spec,
        technique_id: str,
        now: datetime,
    ) -> ActionIR:
        """Build a bounded ActionIR from a validated ActionProposalSpec."""
        return ActionIR(
            action_id=uuid4(),
            blueprint_id=uuid4(),
            technique_id=technique_id,
            action_type=ActionType.PROCESS_EXEC,
            target=spec.target,
            run_as_user=spec.run_as_user,
            executable=spec.executable,
            arguments=list(spec.arguments),
            max_execution_seconds=self.boundary.constraints.max_execution_seconds,
            max_stdout_bytes=self.boundary.constraints.max_stdout_bytes,
            issued_at=now,
            expires_at=now + timedelta(seconds=BLUEPRINT_VALIDITY_SECONDS),
        )

    @staticmethod
    def _sign_kwargs(action: ActionIR) -> dict:
        return {
            "blueprint_id": action.blueprint_id,
            "action_id": action.action_id,
            "technique_id": action.technique_id,
            "target": action.target,
            "executable": action.executable,
            "arguments": action.arguments,
            "run_as_user": action.run_as_user,
            "issued_at": action.issued_at,
            "expires_at": action.expires_at,
        }