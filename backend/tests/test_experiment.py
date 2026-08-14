import pytest
import uuid
from datetime import datetime, timezone, timedelta
from sentinelforge.domain.experiment import (
    SecurityObjective,
    AdversarialScenario,
    ExecutionPlan,
    ExperimentConstraints,
    RiskLevel,
    PolicyDecisionStatus,
)
from sentinelforge.domain.action_ir import ActionIR, ActionType
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary


def test_experiment_domain_models():
    org_id = uuid.uuid4()
    obj = SecurityObjective(
        organization_id=org_id,
        title="Credential Access Coverage",
        description="Verify detection of /etc/shadow access attempts",
    )
    assert obj.title == "Credential Access Coverage"
    assert obj.default_risk_level == RiskLevel.MEDIUM

    scenario = AdversarialScenario(
        objective_id=obj.objective_id,
        organization_id=org_id,
        title="Read Shadow File via Cat",
        strategy_description="Execute cat /etc/shadow in target container",
        technique_ids=["T1003.008"],
        proposed_risk_level=RiskLevel.MEDIUM,
    )
    assert scenario.proposed_risk_level == RiskLevel.MEDIUM
    assert "T1003.008" in scenario.technique_ids


def test_safety_boundary_scenario_evaluation():
    org_id = uuid.uuid4()
    boundary = ExperimentSafetyBoundary(
        constraints=ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM)
    )

    # Allowed scenario
    scenario_ok = AdversarialScenario(
        objective_id=uuid.uuid4(),
        organization_id=org_id,
        title="Low Risk Test",
        strategy_description="Read file",
        technique_ids=["T1059"],
        proposed_risk_level=RiskLevel.LOW,
    )
    decision_ok = boundary.evaluate_scenario(scenario_ok)
    assert decision_ok.status == PolicyDecisionStatus.ALLOWED

    # Denied scenario (risk too high)
    scenario_high = AdversarialScenario(
        objective_id=uuid.uuid4(),
        organization_id=org_id,
        title="High Risk Test",
        strategy_description="Critical test",
        technique_ids=["T1059"],
        proposed_risk_level=RiskLevel.HIGH,
    )
    decision_denied = boundary.evaluate_scenario(scenario_high)
    assert decision_denied.status == PolicyDecisionStatus.DENIED
    assert "exceeds maximum permitted risk" in decision_denied.reason


def test_safety_boundary_action_ir_evaluation():
    org_id = uuid.uuid4()
    boundary = ExperimentSafetyBoundary()

    now = datetime.now(timezone.utc)
    valid_ir = ActionIR(
        action_id=uuid.uuid4(),
        blueprint_id=uuid.uuid4(),
        technique_id="T1059.004",
        action_type=ActionType.PROCESS_EXEC,
        target="sentinelforge-target",
        executable="/usr/bin/bash",
        arguments=["-c", "whoami"],
        run_as_user="labuser",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    decision = boundary.evaluate_action_ir(valid_ir, org_id=org_id, current_time=now)
    assert decision.status == PolicyDecisionStatus.ALLOWED

    # Unauthorized target
    invalid_target_ir = ActionIR(
        action_id=uuid.uuid4(),
        blueprint_id=uuid.uuid4(),
        technique_id="T1059.004",
        action_type=ActionType.PROCESS_EXEC,
        target="unauthorized-host",
        executable="/usr/bin/bash",
        arguments=["-c", "whoami"],
        run_as_user="labuser",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )
    decision_target = boundary.evaluate_action_ir(invalid_target_ir, org_id=org_id, current_time=now)
    assert decision_target.status == PolicyDecisionStatus.DENIED
    assert "not in authorized targets list" in decision_target.reason
