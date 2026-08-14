"""SentinelForge Integration Tests — End-to-End Red/Blue Detection Remediation Pipeline

Exercises the complete closed-loop workflow against real infrastructure boundaries:
RedAgentPlanner -> SafetyBoundary -> PolicyEngine -> SignedBlueprint -> ContainerLinuxAdapter ->
Telemetry -> SigmaEngine -> DetectionGapEvaluator -> DETECTION_GAP -> BlueAgentAnalyst ->
CandidateSigmaRule -> SigmaRuleValidator -> RuleValidationSandbox -> RetestOrchestrator ->
Authorized Retest -> Telemetry -> DetectionGapEvaluator -> DETECTED -> RetestResult ->
ExerciseStateMachine -> VERIFIED.
"""

from datetime import datetime, timezone
from uuid import uuid4
import pytest

from sentinelforge.agents.blue_agent import (
    BlueAgentAnalyst,
    RetestOrchestrator,
    RuleValidationSandbox,
    SigmaRuleValidator,
)
from sentinelforge.agents.red_agent import RedAgentPlanner
from sentinelforge.detection.evaluator import (
    ActionDetectionOutcome,
    DetectionGapEvaluator,
    ScenarioDetectionOutcome,
)
from sentinelforge.detection.normalizer import NormalizedEvent
from sentinelforge.detection.sigma_engine import DetectionOutcome, SigmaEngine
from sentinelforge.domain.experiment import (
    CandidateSigmaRule,
    RetestResult,
    SecurityObjective,
    ValidationSandboxStatus,
)
from sentinelforge.domain.state_machine import ExerciseStateMachine
from sentinelforge.simulation.adapter import ContainerLinuxAdapter

pytestmark = [pytest.mark.integration, pytest.mark.docker]


def test_full_closed_loop_e2e_remediation(require_docker, monkeypatch):
    """Test full E2E Red/Blue detection remediation loop using ContainerLinuxAdapter."""
    # 1. Initialize Red Agent, Adapter, SigmaEngine, and DetectionGapEvaluator
    red_planner = RedAgentPlanner(signing_key="sentinelforge-e2e-key", key_id="key-e2e")
    adapter = ContainerLinuxAdapter()
    assert adapter.health_check() is True

    objective = SecurityObjective(
        objective_id=uuid4(),
        organization_id=uuid4(),
        title="E2E Credential Access Protection",
        description="Verify defensive detection and blue agent remediation for shadow file access",
    )

    # 2. Execute Initial Red Agent Plan (Credential Access Strategy)
    plan_res = red_planner.plan_scenario(objective=objective, strategy_type="credential_dump_shadow")
    assert plan_res.is_allowed is True
    assert len(plan_res.actions) == 1
    action_ir = plan_res.actions[0]

    # 3. Execute bounded command via ContainerLinuxAdapter on sentinelforge-target
    exit_code, stdout_bytes, stderr_bytes, truncated, timed_out = adapter.execute_bounded(
        executable=action_ir.executable,
        arguments=action_ir.arguments,
        run_as_user=action_ir.run_as_user,
        timeout=30,
    )
    assert exit_code != 0  # labuser shadow access should yield non-zero permission denied

    # 4. Normalize execution telemetry
    cmd_line = " ".join(action_ir.arguments) if action_ir.arguments else action_ir.executable
    scenario_id_str = str(plan_res.scenario.scenario_id)

    malicious_event = NormalizedEvent(
        event_id=str(uuid4()),
        correlation_id=scenario_id_str,
        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        source="linux_auditd",
        EventType="execve",
        ProcessName="cat",
        Executable=action_ir.executable,
        CommandLine=cmd_line,
        UserName=action_ir.run_as_user,
        UserUid=1000,
        TargetFile="/etc/shadow",
        ContainerName="sentinelforge-target",
        ContainerId="c_sentinel",
        ParentProcess="bash",
        raw_event_hash=str(hash(cmd_line + str(exit_code))),
    )

    benign_event = NormalizedEvent(
        event_id=str(uuid4()),
        correlation_id=scenario_id_str,
        timestamp=datetime.now(timezone.utc).isoformat() + "Z",
        source="linux_auditd",
        EventType="execve",
        ProcessName="bash",
        Executable="/usr/bin/bash",
        CommandLine="whoami",
        UserName="labuser",
        UserUid=1000,
        TargetFile=None,
        ContainerName="sentinelforge-target",
        ContainerId="c_sentinel",
        ParentProcess="bash",
        raw_event_hash="hash_benign",
    )

    # 5. Evaluate Initial Telemetry -> Expect DETECTION_GAP (no rule registered yet)
    sigma_engine = SigmaEngine()
    gap_evaluator = DetectionGapEvaluator()

    before_outcome = gap_evaluator.evaluate_scenario(
        scenario_id=plan_res.scenario.scenario_id,
        actions=plan_res.actions,
        events=[malicious_event],
        sigma_engine=sigma_engine,
        organization_id=objective.organization_id,
    )
    assert before_outcome.overall_outcome == DetectionOutcome.DETECTION_GAP
    assert len(before_outcome.gap_action_ids) == 1

    # 6. Blue Agent Analyst analyzes detection gap and derives CandidateSigmaRule
    analyst = BlueAgentAnalyst()
    gaps = analyst.analyze_gap(before_outcome, actions=plan_res.actions)
    assert len(gaps) == 1
    assert gaps[0].root_cause == "NO_RULE_MATCH"

    candidate_rule = analyst.propose_candidate_rule(
        gap_analysis=gaps[0], action=action_ir, telemetry_events=[malicious_event]
    )
    assert candidate_rule.source_scenario_id == str(plan_res.scenario.scenario_id)
    assert candidate_rule.source_action_ids == [str(action_ir.action_id)]

    # 7. Validate Candidate Sigma Rule syntax, schema, and false-positive immunity
    validator = SigmaRuleValidator()
    is_valid, val_err = validator.validate_candidate_rule(candidate_rule, expected_technique="T1003.008")
    assert is_valid is True

    sandbox = RuleValidationSandbox()
    sandbox_res = sandbox.validate_candidate_rule(candidate_rule, [malicious_event], [benign_event])
    assert sandbox_res.status == ValidationSandboxStatus.ACCEPTED

    # 8. Retest Orchestrator prepares RetestRequest & executes authorized retest
    orchestrator = RetestOrchestrator()
    retest_req = orchestrator.prepare_retest(
        scenario_id=before_outcome.scenario_id,
        gap_action_ids=before_outcome.gap_action_ids,
        candidate_rules=[candidate_rule],
        validation_result=sandbox_res,
    )

    retest_res = orchestrator.execute_retest(
        retest_request=retest_req,
        objective=objective,
        red_planner=red_planner,
        adapter=adapter,
        sigma_engine=sigma_engine,
        gap_evaluator=gap_evaluator,
        before_outcome=before_outcome,
        strategy_type="credential_dump_shadow",
    )

    assert retest_res.before_outcome == "DETECTION_GAP"
    assert retest_res.after_outcome == "DETECTED"
    assert retest_res.detection_improved is True
    assert candidate_rule.rule_id in retest_res.validated_rule_ids

    # 9. ExerciseStateMachine transition to VERIFIED
    final_state = ExerciseStateMachine.transition("RETESTING", "VERIFIED", retest_result=retest_res)
    assert final_state == "VERIFIED"
