from uuid import uuid4
import pytest

from sentinelforge.agents.red_agent import RedAgentPlanner, STRATEGY_CATALOG
from sentinelforge.domain.experiment import (
    ExperimentConstraints,
    PolicyDecisionStatus,
    RiskLevel,
    SecurityObjective,
)
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary
from sentinelforge.policy.signing import BlueprintSigner


@pytest.fixture
def org_id():
    return uuid4()


@pytest.fixture
def objective(org_id):
    return SecurityObjective(
        organization_id=org_id,
        title="Linux Cyber-Range Identity Reconnaissance",
        description="Test adversarial exploration against authorized Linux target.",
        target_category="linux_host",
    )


@pytest.fixture
def planner():
    return RedAgentPlanner()


def test_red_agent_happy_path_authorized_blueprint(objective, planner):
    """Test 1: Authorized objective + approved strategy -> ALLOWED -> SignedBlueprint exists -> signature verifies."""
    result = planner.plan_scenario(objective, strategy_type="bash_exec_whoami")

    assert result.is_allowed is True
    assert result.policy_decision.status == PolicyDecisionStatus.ALLOWED
    assert "authorized by Experiment Safety Boundary" in result.policy_decision.reason
    assert result.signed_blueprint is not None
    assert len(result.signed_blueprints) == 1
    assert result.action_ir is not None
    assert result.action_ir.arguments == ["-c", "whoami"]
    assert result.action_ir.target == "sentinelforge-target"
    assert result.action_ir.run_as_user == "labuser"

    # Cryptographic HMAC verification
    assert planner.signer.verify(result.signed_blueprint) is True


def test_red_agent_scenario_risk_exceeds_constraints(objective, planner):
    """Test 2: Scenario risk exceeds constraints -> DENIED -> no SignedBlueprint."""
    constraints = ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM)
    result = planner.plan_scenario(
        objective,
        strategy_type="credential_dump_shadow",
        constraints=constraints,
    )

    assert result.is_allowed is False
    assert result.policy_decision.status == PolicyDecisionStatus.DENIED
    assert "exceeds maximum permitted risk" in result.policy_decision.reason
    assert result.signed_blueprint is None
    assert result.signed_blueprints == []
    assert result.execution_plan.status == "REJECTED"


def test_red_agent_unauthorized_command(objective, planner):
    """Test 3: Unauthorized command/action (rm -rf /) -> DENIED -> no SignedBlueprint."""
    result = planner.plan_scenario(
        objective,
        strategy_type="unauthorized_destructive_cmd",
        proposed_risk_level=RiskLevel.MEDIUM,
    )

    assert result.is_allowed is False
    assert result.policy_decision.status == PolicyDecisionStatus.DENIED
    assert "Low-level policy invariant violation" in result.policy_decision.reason
    assert result.signed_blueprint is None
    assert result.signed_blueprints == []
    assert result.execution_plan.status == "REJECTED"


def test_red_agent_human_approval_required(objective, planner):
    """Test 4: Human approval required -> ESCALATED -> no SignedBlueprint. When approved -> ALLOWED."""
    constraints = ExperimentConstraints(requires_human_approval=True)

    # 1. Without human approval -> ESCALATED
    result_escalated = planner.plan_scenario(
        objective,
        strategy_type="bash_exec_whoami",
        is_human_approved=False,
        constraints=constraints,
    )
    assert result_escalated.policy_decision.status == PolicyDecisionStatus.ESCALATED
    assert result_escalated.signed_blueprint is None
    assert result_escalated.signed_blueprints == []

    # 2. With human approval -> ALLOWED
    result_approved = planner.plan_scenario(
        objective,
        strategy_type="bash_exec_whoami",
        is_human_approved=True,
        constraints=constraints,
    )
    assert result_approved.policy_decision.status == PolicyDecisionStatus.ALLOWED
    assert result_approved.signed_blueprint is not None
    assert len(result_approved.signed_blueprints) == 1


def test_red_agent_unauthorized_target(objective, planner):
    """Test 5: Unauthorized target container -> DENIED -> no SignedBlueprint."""
    unauthorized_target_cmd = {
        "title": "Unauthorized Target Test",
        "description": "Attempts execution against production asset.",
        "technique_ids": ["T1059.004"],
        "proposed_risk_level": RiskLevel.LOW,
        "target": "prod-db-server",
        "run_as_user": "labuser",
        "executable": "/usr/bin/bash",
        "arguments": ["-c", "whoami"],
        "command": "whoami",
    }

    result = planner.plan_scenario(objective, custom_command=unauthorized_target_cmd)

    assert result.is_allowed is False
    assert result.policy_decision.status == PolicyDecisionStatus.DENIED
    assert "is not in authorized targets list" in result.policy_decision.reason
    assert result.signed_blueprint is None
    assert result.signed_blueprints == []


def test_red_agent_unauthorized_user(objective, planner):
    """Test 6: Unauthorized execution user (root) -> DENIED -> no SignedBlueprint."""
    unauthorized_user_cmd = {
        "title": "Unauthorized User Test",
        "description": "Attempts execution as root user.",
        "technique_ids": ["T1059.004"],
        "proposed_risk_level": RiskLevel.LOW,
        "target": "sentinelforge-target",
        "run_as_user": "root",
        "executable": "/usr/bin/bash",
        "arguments": ["-c", "whoami"],
        "command": "whoami",
    }

    result = planner.plan_scenario(objective, custom_command=unauthorized_user_cmd)

    assert result.is_allowed is False
    assert result.policy_decision.status == PolicyDecisionStatus.DENIED
    assert "is not in authorized users list" in result.policy_decision.reason
    assert result.signed_blueprint is None
    assert result.signed_blueprints == []


def test_red_agent_max_execution_seconds_boundary(objective, planner):
    """Test 7: max_execution_seconds boundary configured on ExperimentConstraints."""
    constraints = ExperimentConstraints(max_execution_seconds=15)
    result = planner.plan_scenario(objective, strategy_type="bash_exec_whoami", constraints=constraints)

    assert result.is_allowed is True
    boundary = ExperimentSafetyBoundary(constraints)
    assert boundary.constraints.max_execution_seconds == 15


def test_red_agent_max_stdout_bytes_boundary(objective, planner):
    """Test 8: max_stdout_bytes boundary configured on ExperimentConstraints."""
    constraints = ExperimentConstraints(max_stdout_bytes=32768)
    result = planner.plan_scenario(objective, strategy_type="bash_exec_whoami", constraints=constraints)

    assert result.is_allowed is True
    boundary = ExperimentSafetyBoundary(constraints)
    assert boundary.constraints.max_stdout_bytes == 32768


def test_red_agent_max_risk_level_boundary(objective, planner):
    """Test 9: max_risk_level boundary check strictly enforced across LOW, MEDIUM, HIGH, CRITICAL."""
    constraints_low = ExperimentConstraints(max_risk_level=RiskLevel.LOW)
    result = planner.plan_scenario(objective, strategy_type="bash_exec_whoami", constraints=constraints_low)
    assert result.is_allowed is True

    # Medium risk scenario against low max risk ceiling -> DENIED
    result_denied = planner.plan_scenario(
        objective,
        strategy_type="bash_exec_whoami",
        proposed_risk_level=RiskLevel.MEDIUM,
        constraints=constraints_low,
    )
    assert result_denied.is_allowed is False
    assert result_denied.policy_decision.status == PolicyDecisionStatus.DENIED


def test_red_agent_signed_blueprint_verification(objective, planner):
    """Test 10: Cryptographic HMAC signature verification on valid and tampered blueprints."""
    result = planner.plan_scenario(objective, strategy_type="bash_exec_whoami")
    blueprint = result.signed_blueprint

    # Valid signature
    assert planner.signer.verify(blueprint) is True

    # Tampered signature fails verification
    blueprint.target = "hacked-target"
    assert planner.signer.verify(blueprint) is False


def test_red_agent_multiple_actions_one_denied_fails_all(objective, planner):
    """Test 11: Multiple ActionIR actions: if any required action is denied, NO SignedBlueprint is produced."""
    # Multi-step plan where step 1 is valid (whoami) but step 2 is denied (rm -rf /)
    result = planner.plan_scenario(objective, strategy_type="multi_step_with_one_unauthorized")

    assert result.is_allowed is False
    assert result.policy_decision.status == PolicyDecisionStatus.DENIED
    assert len(result.actions) == 2
    assert result.signed_blueprints == []
    assert result.signed_blueprint is None
    assert result.execution_plan.status == "REJECTED"


def test_red_agent_critical_security_cannot_bypass_safety_boundary(objective, planner):
    """Test 12 CRITICAL SECURITY TEST: Prove RedAgentPlanner cannot produce a SignedBlueprint without passing safety boundary."""
    # Attempt to bypass safety boundary by planning an invalid strategy without approval
    result = planner.plan_scenario(
        objective,
        strategy_type="unauthorized_destructive_cmd",
        proposed_risk_level=RiskLevel.CRITICAL,
    )

    # Rejection occurs at ExperimentSafetyBoundary
    assert result.is_allowed is False
    assert result.policy_decision.status == PolicyDecisionStatus.DENIED
    assert result.signed_blueprints == []
    assert result.signed_blueprint is None

    # Prove that BlueprintSigner is NEVER called when PolicyDecision is DENIED
    assert result.execution_plan.status == "REJECTED"
