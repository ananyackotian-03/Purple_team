"""SentinelForge — Phase 2: Safety Boundary Verification.

Proves that the ExperimentSafetyBoundary correctly:
- Allows proposals that satisfy all constraints
- Rejects forbidden commands, targets, users, and risk levels
- Enforces human approval requirements
- Records audit decisions
- Delegates correctly to PolicyEngine for low-level checks
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone, timedelta

from sentinelforge.domain.action_ir import ActionIR, ActionType
from sentinelforge.domain.experiment import (
    AdversarialScenario,
    ExperimentConstraints,
    PolicyDecision,
    PolicyDecisionStatus,
    RiskLevel,
    SecurityObjective,
)
from sentinelforge.domain.exceptions import SecurityRejection
from sentinelforge.policy.engine import PolicyEngine
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_scenario(
    risk: RiskLevel = RiskLevel.MEDIUM,
    org_id=None,
) -> AdversarialScenario:
    return AdversarialScenario(
        objective_id=uuid4(),
        organization_id=org_id or uuid4(),
        title="Test Scenario",
        strategy_description="Execute test command",
        technique_ids=["T1059"],
        proposed_risk_level=risk,
    )


def _make_action(
    executable="/usr/bin/bash",
    arguments=None,
    target="sentinelforge-target",
    user="labuser",
    issued_at=None,
    expires_at=None,
) -> ActionIR:
    now = issued_at or datetime.now(timezone.utc)
    exp = expires_at or (now + timedelta(minutes=5))
    return ActionIR(
        action_id=uuid4(),
        blueprint_id=uuid4(),
        technique_id="T1059.004",
        action_type=ActionType.PROCESS_EXEC,
        target=target,
        executable=executable,
        arguments=arguments or ["-c", "whoami"],
        run_as_user=user,
        issued_at=now,
        expires_at=exp,
    )


# ---------------------------------------------------------------------------
# Scenario-level evaluation
# ---------------------------------------------------------------------------

class TestScenarioEvaluation:
    """Tests for ExperimentSafetyBoundary.evaluate_scenario."""

    def test_allowed_scenario(self):
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(max_risk_level=RiskLevel.HIGH)
        )
        scenario = _make_scenario(risk=RiskLevel.MEDIUM)
        decision = boundary.evaluate_scenario(scenario)
        assert decision.status == PolicyDecisionStatus.ALLOWED
        assert "authorized" in decision.reason.lower()

    def test_critical_risk_exceeds_medium_limit(self):
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM)
        )
        scenario = _make_scenario(risk=RiskLevel.CRITICAL)
        decision = boundary.evaluate_scenario(scenario)
        assert decision.status == PolicyDecisionStatus.DENIED
        assert "exceeds maximum permitted risk" in decision.reason

    def test_high_risk_exceeds_low_limit(self):
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW)
        )
        scenario = _make_scenario(risk=RiskLevel.HIGH)
        decision = boundary.evaluate_scenario(scenario)
        assert decision.status == PolicyDecisionStatus.DENIED

    def test_low_risk_allowed_under_high_limit(self):
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(max_risk_level=RiskLevel.HIGH)
        )
        scenario = _make_scenario(risk=RiskLevel.LOW)
        decision = boundary.evaluate_scenario(scenario)
        assert decision.status == PolicyDecisionStatus.ALLOWED

    def test_human_approval_required_but_not_given(self):
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(
                max_risk_level=RiskLevel.HIGH,
                requires_human_approval=True,
            )
        )
        scenario = _make_scenario(risk=RiskLevel.LOW)
        decision = boundary.evaluate_scenario(scenario, is_human_approved=False)
        assert decision.status == PolicyDecisionStatus.ESCALATED
        assert "human approval" in decision.reason.lower()

    def test_human_approval_required_and_given(self):
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(
                max_risk_level=RiskLevel.HIGH,
                requires_human_approval=True,
            )
        )
        scenario = _make_scenario(risk=RiskLevel.LOW)
        decision = boundary.evaluate_scenario(scenario, is_human_approved=True)
        assert decision.status == PolicyDecisionStatus.ALLOWED

    def test_boundary_records_decision_to_db(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sentinelforge.db.models import Base, PolicyDecisionRecord

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        db = Session()

        boundary = ExperimentSafetyBoundary()
        scenario = _make_scenario()
        decision = boundary.evaluate_scenario(scenario, db_session=db)
        assert decision.status == PolicyDecisionStatus.ALLOWED
        count = db.query(PolicyDecisionRecord).count()
        assert count == 1

    def test_boundary_skips_db_when_none(self):
        boundary = ExperimentSafetyBoundary()
        scenario = _make_scenario()
        decision = boundary.evaluate_scenario(scenario, db_session=None)
        assert decision.status == PolicyDecisionStatus.ALLOWED


# ---------------------------------------------------------------------------
# ActionIR-level evaluation
# ---------------------------------------------------------------------------

class TestActionIREvaluation:
    """Tests for ExperimentSafetyBoundary.evaluate_action_ir."""

    def test_allowed_action_ir(self):
        boundary = ExperimentSafetyBoundary()
        org_id = uuid4()
        ir = _make_action()
        decision = boundary.evaluate_action_ir(ir, org_id=org_id, current_time=datetime.now(timezone.utc))
        assert decision.status == PolicyDecisionStatus.ALLOWED
        assert "authorized" in decision.reason.lower()

    def test_unauthorized_target_rejected(self):
        boundary = ExperimentSafetyBoundary()
        org_id = uuid4()
        ir = _make_action(target="production-database")
        decision = boundary.evaluate_action_ir(ir, org_id=org_id)
        assert decision.status == PolicyDecisionStatus.DENIED
        assert "not in authorized targets list" in decision.reason

    def test_unauthorized_user_rejected(self):
        boundary = ExperimentSafetyBoundary()
        org_id = uuid4()
        ir = _make_action(user="root")
        decision = boundary.evaluate_action_ir(ir, org_id=org_id)
        assert decision.status == PolicyDecisionStatus.DENIED
        assert "not in authorized users list" in decision.reason

    def test_unauthorized_executable_rejected(self):
        boundary = ExperimentSafetyBoundary()
        org_id = uuid4()
        ir = _make_action(executable="/usr/bin/python3", arguments=["-c", "import os"])
        decision = boundary.evaluate_action_ir(ir, org_id=org_id)
        assert decision.status == PolicyDecisionStatus.DENIED
        assert "low-level policy invariant" in decision.reason.lower()

    def test_unauthorized_bash_command_rejected(self):
        boundary = ExperimentSafetyBoundary()
        org_id = uuid4()
        ir = _make_action(executable="/usr/bin/bash", arguments=["-c", "curl http://evil.com"])
        decision = boundary.evaluate_action_ir(ir, org_id=org_id)
        assert decision.status == PolicyDecisionStatus.DENIED

    def test_path_traversal_rejected(self):
        boundary = ExperimentSafetyBoundary()
        org_id = uuid4()
        ir = _make_action(executable="/usr/bin/cat", arguments=["/etc/../etc/shadow"])
        decision = boundary.evaluate_action_ir(ir, org_id=org_id)
        assert decision.status == PolicyDecisionStatus.DENIED

    def test_expired_blueprint_rejected(self):
        boundary = ExperimentSafetyBoundary()
        org_id = uuid4()
        now = datetime.now(timezone.utc)
        ir = _make_action(
            issued_at=now - timedelta(minutes=10),
            expires_at=now - timedelta(minutes=5),
        )
        decision = boundary.evaluate_action_ir(ir, org_id=org_id, current_time=now)
        assert decision.status == PolicyDecisionStatus.DENIED
        assert "expired" in decision.reason.lower()

    def test_future_issued_blueprint_rejected(self):
        boundary = ExperimentSafetyBoundary()
        org_id = uuid4()
        now = datetime.now(timezone.utc)
        ir = _make_action(
            issued_at=now + timedelta(minutes=10),
            expires_at=now + timedelta(minutes=20),
        )
        decision = boundary.evaluate_action_ir(ir, org_id=org_id, current_time=now)
        assert decision.status == PolicyDecisionStatus.DENIED
        assert "future" in decision.reason.lower()

    def test_boundary_records_action_decision_to_db(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sentinelforge.db.models import Base, PolicyDecisionRecord

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        db = Session()

        boundary = ExperimentSafetyBoundary()
        org_id = uuid4()
        ir = _make_action()
        decision = boundary.evaluate_action_ir(ir, org_id=org_id, db_session=db)
        assert decision.status == PolicyDecisionStatus.ALLOWED
        assert db.query(PolicyDecisionRecord).count() == 1

    def test_boundary_records_denial_to_db(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sentinelforge.db.models import Base, PolicyDecisionRecord

        engine = create_engine("sqlite:///:memory:")
        Base.metadata.create_all(engine)
        Session = sessionmaker(bind=engine)
        db = Session()

        boundary = ExperimentSafetyBoundary()
        org_id = uuid4()
        ir = _make_action(user="root")
        decision = boundary.evaluate_action_ir(ir, org_id=org_id, db_session=db)
        assert decision.status == PolicyDecisionStatus.DENIED
        assert db.query(PolicyDecisionRecord).count() == 1


# ---------------------------------------------------------------------------
# PolicyEngine direct validation
# ---------------------------------------------------------------------------

class TestPolicyEngineValidation:
    """Tests for the low-level PolicyEngine.validate."""

    def test_allowed_action_passes(self):
        ir = _make_action()
        result = PolicyEngine.validate(ir, current_time=datetime.now(timezone.utc))
        assert result is True

    def test_unauthorized_executable_raises(self):
        ir = _make_action(executable="/usr/bin/python3", arguments=["-c", "x=1"])
        with pytest.raises(SecurityRejection) as exc_info:
            PolicyEngine.validate(ir, current_time=datetime.now(timezone.utc))
        assert exc_info.value.code.value == "INVALID_EXECUTABLE"

    def test_unauthorized_bash_command_raises(self):
        ir = _make_action(executable="/usr/bin/bash", arguments=["-c", "wget http://evil.com"])
        with pytest.raises(SecurityRejection):
            PolicyEngine.validate(ir, current_time=datetime.now(timezone.utc))

    def test_unauthorized_target_raises(self):
        ir = _make_action(target="prod-db")
        with pytest.raises(SecurityRejection) as exc_info:
            PolicyEngine.validate(ir, current_time=datetime.now(timezone.utc))
        assert exc_info.value.code.value == "INVALID_TARGET"

    def test_unauthorized_user_raises(self):
        ir = _make_action(user="root")
        with pytest.raises(SecurityRejection) as exc_info:
            PolicyEngine.validate(ir, current_time=datetime.now(timezone.utc))
        assert exc_info.value.code.value == "UNAUTHORIZED_USER"

    def test_expired_blueprint_raises(self):
        now = datetime.now(timezone.utc)
        ir = _make_action(
            issued_at=now - timedelta(minutes=10),
            expires_at=now - timedelta(minutes=5),
        )
        with pytest.raises(SecurityRejection) as exc_info:
            PolicyEngine.validate(ir, current_time=now)
        assert exc_info.value.code.value == "EXPIRED_BLUEPRINT"

    def test_future_issued_blueprint_raises(self):
        now = datetime.now(timezone.utc)
        ir = _make_action(
            issued_at=now + timedelta(minutes=10),
            expires_at=now + timedelta(minutes=20),
        )
        with pytest.raises(SecurityRejection) as exc_info:
            PolicyEngine.validate(ir, current_time=now)
        assert "future" in exc_info.value.message.lower()

    def test_bash_without_dash_c_raises(self):
        ir = _make_action(executable="/usr/bin/bash", arguments=["whoami"])
        with pytest.raises(SecurityRejection) as exc_info:
            PolicyEngine.validate(ir, current_time=datetime.now(timezone.utc))
        assert exc_info.value.code.value == "INVALID_ARGUMENTS"

    def test_cat_path_traversal_raises(self):
        ir = _make_action(executable="/usr/bin/cat", arguments=["/etc/../etc/shadow"])
        with pytest.raises(SecurityRejection):
            PolicyEngine.validate(ir, current_time=datetime.now(timezone.utc))

    def test_allowed_cat_etc_shadow(self):
        ir = _make_action(executable="/usr/bin/cat", arguments=["/etc/shadow"])
        result = PolicyEngine.validate(ir, current_time=datetime.now(timezone.utc))
        assert result is True


# ---------------------------------------------------------------------------
# Audit trail integrity
# ---------------------------------------------------------------------------

class TestAuditTrail:
    """Verify that every decision generates an audit record."""

    def test_allowed_scenario_has_decision_id(self):
        boundary = ExperimentSafetyBoundary()
        scenario = _make_scenario()
        decision = boundary.evaluate_scenario(scenario)
        assert decision.decision_id is not None

    def test_denied_scenario_has_decision_id(self):
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW)
        )
        scenario = _make_scenario(risk=RiskLevel.CRITICAL)
        decision = boundary.evaluate_scenario(scenario)
        assert decision.decision_id is not None
        assert decision.status == PolicyDecisionStatus.DENIED

    def test_action_decision_captures_org_id(self):
        boundary = ExperimentSafetyBoundary()
        org_id = uuid4()
        ir = _make_action()
        decision = boundary.evaluate_action_ir(ir, org_id=org_id)
        assert decision.organization_id == org_id

    def test_action_decision_captures_blueprint_id(self):
        boundary = ExperimentSafetyBoundary()
        ir = _make_action()
        decision = boundary.evaluate_action_ir(ir, org_id=uuid4())
        assert decision.blueprint_id == ir.blueprint_id

    def test_evaluated_at_is_set(self):
        boundary = ExperimentSafetyBoundary()
        before = datetime.now(timezone.utc)
        scenario = _make_scenario()
        decision = boundary.evaluate_scenario(scenario)
        after = datetime.now(timezone.utc)
        assert before <= decision.evaluated_at <= after


# ---------------------------------------------------------------------------
# Risk boundary edge cases
# ---------------------------------------------------------------------------

class TestRiskBoundaryEdgeCases:
    def test_critical_boundary_at_exactly_max(self):
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(max_risk_level=RiskLevel.HIGH)
        )
        scenario = _make_scenario(risk=RiskLevel.HIGH)
        decision = boundary.evaluate_scenario(scenario)
        assert decision.status == PolicyDecisionStatus.ALLOWED

    def test_critical_boundary_one_above_max(self):
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM)
        )
        scenario = _make_scenario(risk=RiskLevel.HIGH)
        decision = boundary.evaluate_scenario(scenario)
        assert decision.status == PolicyDecisionStatus.DENIED

    def test_custom_target_list_respected_by_boundary(self):
        """Boundary accepts custom targets, but PolicyEngine enforces its own invariants."""
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(
                allowed_targets=["custom-target-a", "custom-target-b"]
            )
        )
        # Boundary accepts custom-target-a, but PolicyEngine rejects because
        # its fixed invariant requires "sentinelforge-target"
        ir = _make_action(target="custom-target-a")
        decision = boundary.evaluate_action_ir(ir, org_id=uuid4())
        assert decision.status == PolicyDecisionStatus.DENIED
        assert "low-level policy invariant" in decision.reason.lower()

    def test_custom_target_list_blocks_unknown(self):
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(
                allowed_targets=["custom-target-a"]
            )
        )
        ir = _make_action(target="unknown-target")
        decision = boundary.evaluate_action_ir(ir, org_id=uuid4())
        assert decision.status == PolicyDecisionStatus.DENIED
        assert "not in authorized targets list" in decision.reason

    def test_custom_user_list_respected_by_boundary(self):
        """Boundary accepts custom users, but PolicyEngine enforces its own invariants."""
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(
                allowed_users=["admin", "tester"]
            )
        )
        # Boundary accepts "tester", but PolicyEngine rejects because
        # its fixed invariant requires "labuser"
        ir = _make_action(user="tester")
        decision = boundary.evaluate_action_ir(ir, org_id=uuid4())
        assert decision.status == PolicyDecisionStatus.DENIED
        assert "low-level policy invariant" in decision.reason.lower()

    def test_custom_user_list_blocks_unknown(self):
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(
                allowed_users=["admin"]
            )
        )
        ir = _make_action(user="nobody")
        decision = boundary.evaluate_action_ir(ir, org_id=uuid4())
        assert decision.status == PolicyDecisionStatus.DENIED
        assert "not in authorized users list" in decision.reason

    def test_boundary_plus_policy_engine_only_passes_canonical(self):
        """Only sentinelforge-target + labuser + allowed executable passes both layers."""
        boundary = ExperimentSafetyBoundary()
        ir = _make_action(target="sentinelforge-target", user="labuser")
        decision = boundary.evaluate_action_ir(ir, org_id=uuid4(), current_time=datetime.now(timezone.utc))
        assert decision.status == PolicyDecisionStatus.ALLOWED
