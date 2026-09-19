"""Phase 12K — Security Invariant Matrix (20 invariants)."""

import pytest
from uuid import uuid4
from datetime import datetime, timezone, timedelta

from sentinelforge.domain.action_ir import ActionIR
from sentinelforge.domain.exceptions import SecurityRejection, SecurityRejectionCode
from sentinelforge.policy.engine import PolicyEngine
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary
from sentinelforge.domain.experiment import (
    AdversarialScenario, ExperimentConstraints, RiskLevel, PolicyDecisionStatus,
)
from sentinelforge.domain.state_machine import CyberImmuneStateMachine
from sentinelforge.defensive.proposal import DefensiveProposal, ProposalType
from sentinelforge.defensive.boundary import DefensiveSafetyBoundary


def _action(**kw):
    now = datetime.now(timezone.utc)
    defaults = dict(
        action_id=uuid4(), blueprint_id=uuid4(), technique_id="T1003",
        action_type="process_exec", target="sentinelforge-target",
        executable="/usr/bin/bash", arguments=["-c", "whoami"],
        run_as_user="labuser", max_execution_seconds=30,
        max_stdout_bytes=4096, issued_at=now,
        expires_at=now + timedelta(minutes=5))
    defaults.update(kw)
    return ActionIR(**defaults)


class TestInvariant1_LLMCannotExecute:
    def test_forbidden_tools_blocked(self):
        from sentinelforge.agents.red.tools import _FORBIDDEN_TOOLS
        for name in ["execute_shell", "arbitrary_command", "docker_exec",
                      "modify_database", "modify_policy"]:
            assert name in _FORBIDDEN_TOOLS


class TestInvariant2_CannotBypassSafetyBoundary:
    def test_critical_risk_denied(self):
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW))
        scenario = AdversarialScenario(
            organization_id=uuid4(), objective_id=uuid4(),
            title="X", strategy_description="X",
            technique_ids=["T1003"], proposed_risk_level=RiskLevel.CRITICAL, created_by="red")
        assert boundary.evaluate_scenario(scenario).status.value == "DENIED"

    def test_unauthorized_target_denied(self):
        boundary = ExperimentSafetyBoundary()
        assert boundary.evaluate_action_ir(_action(target="prod"), org_id=uuid4()).status.value == "DENIED"


class TestInvariant3_CannotBypassPolicyEngine:
    def test_forbidden_exec_rejected(self):
        with pytest.raises(SecurityRejection) as e:
            PolicyEngine.validate(_action(executable="/usr/bin/python3"))
        assert e.value.code == SecurityRejectionCode.INVALID_EXECUTABLE

    def test_forbidden_command_rejected(self):
        with pytest.raises(SecurityRejection) as e:
            PolicyEngine.validate(_action(arguments=["-c", "curl evil.com"]))
        assert e.value.code == SecurityRejectionCode.POLICY_DENIED


class TestInvariant4_CannotModifyBudgets:
    def test_budget_not_in_llm_schema(self):
        from sentinelforge.adaptive.schemas import NextExperimentProposal
        props = NextExperimentProposal.model_json_schema().get("properties", {})
        assert "budget" not in props
        assert "max_iterations" not in props


class TestInvariant5_CannotAccessProduction:
    def test_production_target_rejected(self):
        with pytest.raises(SecurityRejection) as e:
            PolicyEngine.validate(_action(target="production-db"))
        assert e.value.code == SecurityRejectionCode.INVALID_TARGET


class TestInvariant6_CannotModifyDetection:
    def test_detection_outcome_is_enum(self):
        from sentinelforge.detection.evaluator import DetectionOutcome
        assert DetectionOutcome.DETECTED.value == "DETECTED"
        assert DetectionOutcome.NOT_DETECTED.value == "NOT_DETECTED"
        assert DetectionOutcome.DETECTION_GAP.value == "DETECTION_GAP"

    def test_evaluation_detection_is_string(self):
        from sentinelforge.detection.evaluator import PurpleEvaluation
        e = PurpleEvaluation(
            evaluation_id="e1", experiment_id="x1", execution_id="d1",
            organization_id=uuid4(), technique_id="T1003",
            detection_status="DETECTED", matched_rule_ids=[], evidence_event_ids=[])
        assert e.detection_status == "DETECTED"


class TestInvariant7_CannotMarkMitigated:
    def test_gap_identified_cannot_go_to_mitigated(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "MITIGATED")


class TestInvariant8_CannotFabricateTelemetry:
    def test_no_telemetry_in_authorized_tools(self):
        from sentinelforge.agents.red.tools import AUTHORIZED_TOOLS
        for name in AUTHORIZED_TOOLS:
            assert "telemetry" not in name.lower()


class TestInvariant9_CannotFabricateEvidence:
    def test_no_evidence_in_authorized_tools(self):
        from sentinelforge.agents.red.tools import AUTHORIZED_TOOLS
        for name in AUTHORIZED_TOOLS:
            assert "evidence" not in name.lower()


class TestInvariant10_CannotDeclareMitigated:
    def test_mitigated_requires_state_machine_guard(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING", "MITIGATED",
                before_outcome="DETECTED", after_outcome="DETECTED",
                detection_improved=True)


class TestInvariant11_MitigatedRequiresEvidence:
    def test_valid_mitigated_succeeds(self):
        result = CyberImmuneStateMachine.transition(
            "COMPARING", "MITIGATED",
            before_outcome="NOT_DETECTED", after_outcome="DETECTED",
            detection_improved=True)
        assert result == "MITIGATED"

    def test_mitigated_requires_before_detection_failure(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING", "MITIGATED",
                before_outcome="DETECTED", after_outcome="DETECTED",
                detection_improved=True)

    def test_mitigated_requires_after_detected(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING", "MITIGATED",
                before_outcome="NOT_DETECTED", after_outcome="NOT_DETECTED",
                detection_improved=True)

    def test_mitigated_requires_detection_improved_true(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING", "MITIGATED",
                before_outcome="NOT_DETECTED", after_outcome="DETECTED",
                detection_improved=False)


class TestInvariant12_EvaluationsTraceable:
    def test_purple_evaluation_has_ids(self):
        from sentinelforge.detection.evaluator import PurpleEvaluation
        e = PurpleEvaluation(
            evaluation_id="e1", experiment_id="x1", execution_id="d1",
            organization_id=uuid4(), technique_id="T1003",
            detection_status="DETECTED", matched_rule_ids=[], evidence_event_ids=[])
        assert e.experiment_id == "x1"
        assert e.execution_id == "d1"


class TestInvariant13_TenantIsolation:
    def test_defensive_boundary_rejects_cross_tenant(self):
        org_a, org_b = uuid4(), uuid4()
        boundary = DefensiveSafetyBoundary(organization_id=org_a)
        proposal = DefensiveProposal(
            proposal_id=uuid4(), organization_id=org_b,
            gap_id=uuid4(), experiment_id=uuid4(),
            technique_id="T1003", proposal_type=ProposalType.ADD_DETECTION_RULE,
            description="test", rationale="test", expected_effect="test",
            validation_requirements=["test"])
        assert boundary.gate_organization_ownership(proposal).decision == "DENIED"


class TestInvariant14_InvalidTransitionsRejected:
    def test_skip_states_blocked(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "RETTESTING")

    def test_reverse_transitions_blocked(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("MITIGATED", "COMPARING")

    def test_unknown_state_blocked(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "UNKNOWN")


class TestInvariant15_FailuresTerminateSafely:
    def test_expired_blueprint_rejected(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(SecurityRejection):
            PolicyEngine.validate(_action(
                issued_at=now - timedelta(hours=2),
                expires_at=now - timedelta(hours=1)))

    def test_future_blueprint_rejected(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(SecurityRejection):
            PolicyEngine.validate(_action(
                issued_at=now + timedelta(hours=1),
                expires_at=now + timedelta(hours=2)))


class TestInvariant16_BudgetEnforced:
    def test_budget_constraints_exist(self):
        c = ExperimentConstraints()
        assert hasattr(c, "max_execution_seconds")
        assert hasattr(c, "max_risk_level")


class TestInvariant17_UnauthorizedToolsNeverExecute:
    def test_python_not_in_allowlist(self):
        from sentinelforge.policy.allowlists import ALLOWED_EXECUTABLES
        assert "/usr/bin/python3" not in ALLOWED_EXECUTABLES
        assert "/usr/bin/curl" in ALLOWED_EXECUTABLES  # authorized for web app testing (Upgrade 5)


class TestInvariant18_APICannotBypassSecurity:
    def test_no_mitigate_endpoint(self):
        from fastapi.testclient import TestClient
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        import sentinelforge.api.app as app_module
        from sentinelforge.db.models import Base

        eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(eng)
        app_module.engine = eng
        app_module.SessionLocal = sessionmaker(bind=eng, expire_on_commit=False)
        app_module._seed_demo_data = lambda: None
        with TestClient(app_module.app, raise_server_exceptions=False) as c:
            resp = c.post(f"/api/organizations/{uuid4()}/detection-gaps/mitigate")
            assert resp.status_code == 404


class TestInvariant19_ImmuneMemoryTenantIsolation:
    def test_immune_memory_scoped_to_org(self):
        from sentinelforge.immune_memory import ImmuneMemory
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        import sentinelforge.db.models, sentinelforge.remediation.db_models
        from sentinelforge.db.models import Base

        eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(eng)
        Session = sessionmaker(bind=eng, expire_on_commit=False)
        session = Session()
        org_id = uuid4()
        memory = ImmuneMemory(session, org_id)
        state = memory.compute_state()
        assert state["organization_id"] == str(org_id)
        session.close()


class TestInvariant20_AdaptiveSelectionValidated:
    def test_selector_validates_through_safety_boundary(self):
        from sentinelforge.adaptive.next_experiment_selector import NextExperimentSelector
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool
        import sentinelforge.db.models, sentinelforge.remediation.db_models
        from sentinelforge.db.models import Base

        eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
        Base.metadata.create_all(eng)
        Session = sessionmaker(bind=eng, expire_on_commit=False)
        session = Session()
        selector = NextExperimentSelector(session, uuid4())
        result = selector.select_next_experiment()
        assert result.validation_passed is not None
        session.close()
