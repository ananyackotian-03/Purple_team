"""Phase 12L — Integration Validation."""

import pytest
from uuid import uuid4
from datetime import datetime, timezone, timedelta

from sentinelforge.domain.action_ir import ActionIR
from sentinelforge.domain.exceptions import SecurityRejection
from sentinelforge.policy.engine import PolicyEngine
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary
from sentinelforge.domain.experiment import (
    AdversarialScenario, ExperimentConstraints, RiskLevel, PolicyDecisionStatus,
)
from sentinelforge.domain.state_machine import CyberImmuneStateMachine
from sentinelforge.defensive.proposal import DefensiveProposal, ProposalType
from sentinelforge.defensive.boundary import DefensiveSafetyBoundary
from sentinelforge.detection.evaluator import PurpleEvaluation, DetectionOutcome


class TestSafetyBoundaryIntegratesWithPolicyEngine:
    def test_boundary_delegates_to_policy_engine(self):
        boundary = ExperimentSafetyBoundary()
        action = ActionIR(
            action_id=uuid4(), blueprint_id=uuid4(), technique_id="T1003",
            action_type="process_exec", target="sentinelforge-target",
            executable="/usr/bin/bash", arguments=["-c", "whoami"],
            run_as_user="labuser", max_execution_seconds=30, max_stdout_bytes=4096,
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
        assert boundary.evaluate_action_ir(action, org_id=uuid4()).status.value == "ALLOWED"

    def test_boundary_blocks_invalid_action(self):
        boundary = ExperimentSafetyBoundary()
        action = ActionIR(
            action_id=uuid4(), blueprint_id=uuid4(), technique_id="T1003",
            action_type="process_exec", target="sentinelforge-target",
            executable="/usr/bin/python3", arguments=["-c", "import os"],
            run_as_user="labuser", max_execution_seconds=30, max_stdout_bytes=4096,
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
        assert boundary.evaluate_action_ir(action, org_id=uuid4()).status.value == "DENIED"


class TestStateMachineIntegratesWithBoundary:
    def test_full_gap_to_mitigated_path(self):
        s = "GAP_IDENTIFIED"
        s = CyberImmuneStateMachine.transition(s, "DEFENSE_PROPOSED")
        s = CyberImmuneStateMachine.transition(s, "DEFENSE_VALIDATED")
        s = CyberImmuneStateMachine.transition(s, "DEFENSE_TESTING")
        s = CyberImmuneStateMachine.transition(s, "RETTESTING")
        s = CyberImmuneStateMachine.transition(s, "COMPARING")
        s = CyberImmuneStateMachine.transition(
            s, "MITIGATED", before_outcome="DETECTION_GAP",
            after_outcome="DETECTED", detection_improved=True)
        s = CyberImmuneStateMachine.transition(s, "NEXT_EXPERIMENT")
        assert s == "NEXT_EXPERIMENT"

    def test_full_gap_to_unresolved_path(self):
        s = "GAP_IDENTIFIED"
        s = CyberImmuneStateMachine.transition(s, "DEFENSE_PROPOSED")
        s = CyberImmuneStateMachine.transition(s, "DEFENSE_VALIDATED")
        s = CyberImmuneStateMachine.transition(s, "DEFENSE_TESTING")
        s = CyberImmuneStateMachine.transition(s, "UNRESOLVED")
        s = CyberImmuneStateMachine.transition(s, "NEXT_EXPERIMENT")
        assert s == "NEXT_EXPERIMENT"


class TestDefensiveBoundaryIntegratesWithStateMachine:
    def test_proposal_validated_through_boundary(self):
        org_id = uuid4()
        boundary = DefensiveSafetyBoundary(organization_id=org_id)
        proposal = DefensiveProposal(
            proposal_id=uuid4(), organization_id=org_id,
            gap_id=uuid4(), experiment_id=uuid4(),
            technique_id="T1003", proposal_type=ProposalType.ADD_DETECTION_RULE,
            description="Add detection rule", rationale="Improve detection",
            expected_effect="Detect T1003", validation_requirements=["Sigma rule"])
        assert boundary.evaluate(proposal).decision == "APPROVED"

    def test_cross_tenant_proposal_rejected(self):
        boundary = DefensiveSafetyBoundary(organization_id=uuid4())
        proposal = DefensiveProposal(
            proposal_id=uuid4(), organization_id=uuid4(),
            gap_id=uuid4(), experiment_id=uuid4(),
            technique_id="T1003", proposal_type=ProposalType.ADD_DETECTION_RULE,
            description="test", rationale="test", expected_effect="test",
            validation_requirements=["test"])
        assert boundary.evaluate(proposal).decision == "DENIED"


class TestBeforeAfterComparisonIntegratesWithStateMachine:
    def test_comparison_determines_improvement(self):
        from sentinelforge.defensive.before_after_comparison import BeforeAfterComparison
        org_id = uuid4()
        before = PurpleEvaluation(
            evaluation_id="b1", experiment_id="e1", execution_id="d1",
            organization_id=org_id, technique_id="T1003",
            detection_status="NOT_DETECTED", matched_rule_ids=[],
            evidence_event_ids=[], expected_detection=True)
        after = PurpleEvaluation(
            evaluation_id="a1", experiment_id="e1", execution_id="d2",
            organization_id=org_id, technique_id="T1003",
            detection_status="DETECTED", matched_rule_ids=["rule-1"],
            evidence_event_ids=["evt-1"], expected_detection=True)
        comp = BeforeAfterComparison.from_evaluations(before, after, org_id)
        assert comp.improved is True

    def test_comparison_rejects_fabricated_data(self):
        from sentinelforge.defensive.before_after_comparison import BeforeAfterComparison
        org_id = uuid4()
        before = PurpleEvaluation(
            evaluation_id="b2", experiment_id="e2", execution_id="d3",
            organization_id=org_id, technique_id="T1003",
            detection_status="DETECTED", matched_rule_ids=[],
            evidence_event_ids=[], expected_detection=True)
        after = PurpleEvaluation(
            evaluation_id="a2", experiment_id="e2", execution_id="d4",
            organization_id=org_id, technique_id="T1003",
            detection_status="DETECTED", matched_rule_ids=[],
            evidence_event_ids=[], expected_detection=True)
        comp = BeforeAfterComparison.from_evaluations(before, after, org_id)
        assert comp.improved is False


class TestFullSecurityStack:
    def test_red_agent_planner_validates_through_full_stack(self):
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(
                max_risk_level=RiskLevel.LOW, requires_human_approval=False))
        scenario = AdversarialScenario(
            organization_id=uuid4(), objective_id=uuid4(),
            title="Low risk", strategy_description="Low risk test",
            technique_ids=["T1003"], proposed_risk_level=RiskLevel.LOW, created_by="red")
        decision = boundary.evaluate_scenario(scenario)
        assert decision.status.value == "ALLOWED"

        action = ActionIR(
            action_id=uuid4(), blueprint_id=uuid4(), technique_id="T1003",
            action_type="process_exec", target="sentinelforge-target",
            executable="/usr/bin/bash", arguments=["-c", "whoami"],
            run_as_user="labuser", max_execution_seconds=30, max_stdout_bytes=4096,
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=5))
        action_decision = boundary.evaluate_action_ir(action, org_id=scenario.organization_id)
        assert action_decision.status.value == "ALLOWED"
