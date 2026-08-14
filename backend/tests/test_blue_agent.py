"""SentinelForge Phase 5 — Blue Agent Analyst & Detection Remediation Pipeline Tests

Validates detection gap analysis, evidence-backed candidate Sigma rule generation,
YAML and schema validation, false-positive immunity in telemetry sandbox,
provenance preservation, retest orchestration through authorized boundaries,
ExerciseStateMachine VERIFIED invariants, and adversarial input safety.
"""

from datetime import datetime, timezone, timedelta
from uuid import uuid4
import pytest
import yaml

from sentinelforge.agents.blue_agent import (
    BlueAgentAnalyst,
    GapAnalysisResult,
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
from sentinelforge.domain.action_ir import ActionIR, ActionType
from sentinelforge.domain.exceptions import SecurityRejection, SecurityRejectionCode
from sentinelforge.domain.experiment import (
    CandidateSigmaRule,
    RetestRequest,
    RetestResult,
    SecurityObjective,
    ValidationSandboxResult,
    ValidationSandboxStatus,
)
from sentinelforge.domain.state_machine import ExerciseStateMachine
from sentinelforge.simulation.adapter import ContainerLinuxAdapter, SimulationAdapter


# Helper fixtures
@pytest.fixture
def mock_objective():
    return SecurityObjective(
        objective_id=uuid4(),
        organization_id=uuid4(),
        title="Test Security Objective for Blue Agent",
        description="Objective targeting Linux credential access",
    )


@pytest.fixture
def sample_action_ir():
    now = datetime.now(timezone.utc)
    return ActionIR(
        action_id=uuid4(),
        blueprint_id=uuid4(),
        technique_id="T1003.008",
        action_type=ActionType.PROCESS_EXEC,
        target="sentinelforge-target",
        run_as_user="labuser",
        executable="/usr/bin/bash",
        arguments=["-c", "cat /etc/shadow"],
        issued_at=now,
        expires_at=now + timedelta(minutes=5),
    )


@pytest.fixture
def sample_malicious_event(sample_action_ir):
    return NormalizedEvent(
        event_id=str(uuid4()),
        correlation_id=str(uuid4()),
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
        raw_event_hash="hash_shadow_access",
    )


@pytest.fixture
def sample_benign_events():
    now = datetime.now(timezone.utc).isoformat() + "Z"
    return [
        NormalizedEvent(
            event_id=str(uuid4()),
            correlation_id=str(uuid4()),
            timestamp=now,
            source="linux_auditd",
            EventType="execve",
            ProcessName="bash",
            Executable="/usr/bin/bash",
            CommandLine="whoami",
            UserName="labuser",
            UserUid=1000,
            TargetFile=None,
            ContainerName="sentinelforge-target",
            ContainerId="c1",
            ParentProcess="bash",
            raw_event_hash="hash_whoami",
        ),
        NormalizedEvent(
            event_id=str(uuid4()),
            correlation_id=str(uuid4()),
            timestamp=now,
            source="linux_auditd",
            EventType="execve",
            ProcessName="id",
            Executable="/usr/bin/id",
            CommandLine="id",
            UserName="labuser",
            UserUid=1000,
            TargetFile=None,
            ContainerName="sentinelforge-target",
            ContainerId="c1",
            ParentProcess="bash",
            raw_event_hash="hash_id",
        ),
    ]



class MockAdapter(SimulationAdapter):
    """Deterministic mock adapter for testing retest execution without Docker daemon."""

    def execute_bounded(self, executable, arguments, run_as_user, timeout=30, constraints=None):
        cmd = " ".join(arguments) if arguments else executable
        if "shadow" in cmd:
            return (1, b"cat: /etc/shadow: Permission denied\n", b"", False, False)
        return (0, b"labuser\n", b"", False, False)

    def cleanup(self):
        pass

    def health_check(self):
        return True


# ---------------------------------------------------------------------------
# Test Cases 1-21
# ---------------------------------------------------------------------------


def test_1_detection_gap_consumed_by_analyst(sample_action_ir):
    """1. Detection gap outcome consumed by analyst."""
    scenario_id = str(uuid4())
    act_outcome = ActionDetectionOutcome(
        action_id=str(sample_action_ir.action_id),
        technique_id="T1003.008",
        outcome=DetectionOutcome.DETECTION_GAP,
        reason="No telemetry observed for shadow access",
    )
    scen_outcome = ScenarioDetectionOutcome(
        scenario_id=scenario_id,
        organization_id=str(uuid4()),
        overall_outcome=DetectionOutcome.DETECTION_GAP,
        action_outcomes=[act_outcome],
        gap_action_ids=[str(sample_action_ir.action_id)],
    )

    analyst = BlueAgentAnalyst()
    gaps = analyst.analyze_gap(scen_outcome, actions=[sample_action_ir])

    assert len(gaps) == 1
    assert gaps[0].scenario_id == scenario_id
    assert gaps[0].action_id == str(sample_action_ir.action_id)
    assert gaps[0].root_cause == "NO_TELEMETRY"


def test_2_technique_id_extraction(sample_action_ir):
    """2. Technique ID correctly extracted from action and gap."""
    analyst = BlueAgentAnalyst()
    act_outcome = ActionDetectionOutcome(
        action_id=str(sample_action_ir.action_id),
        technique_id="T1003.008",
        outcome=DetectionOutcome.NOT_DETECTED,
        evidence_event_ids=["ev-1"],
        reason="Telemetry observed but no rule matched",
    )
    scen_outcome = ScenarioDetectionOutcome(
        scenario_id=str(uuid4()),
        organization_id=str(uuid4()),
        overall_outcome=DetectionOutcome.DETECTION_GAP,
        action_outcomes=[act_outcome],
        gap_action_ids=[str(sample_action_ir.action_id)],
    )

    gaps = analyst.analyze_gap(scen_outcome, actions=[sample_action_ir])
    assert gaps[0].technique_id == "T1003.008"
    assert gaps[0].root_cause == "NO_RULE_MATCH"


def test_3_provenance_generation(sample_action_ir, sample_malicious_event):
    """3. Candidate rule contains immutable x-sentinelforge provenance."""
    analyst = BlueAgentAnalyst()
    gap = GapAnalysisResult(
        scenario_id=str(uuid4()),
        action_id=str(sample_action_ir.action_id),
        technique_id="T1003.008",
        original_outcome="DETECTION_GAP",
        root_cause="NO_TELEMETRY",
        reason="No telemetry",
    )

    candidate = analyst.propose_candidate_rule(gap, action=sample_action_ir, telemetry_events=[sample_malicious_event])
    assert candidate.source_scenario_id == gap.scenario_id
    assert candidate.source_action_ids == [str(sample_action_ir.action_id)]
    assert candidate.technique_id == "T1003.008"

    yaml_text = candidate.to_yaml()
    assert "x-sentinelforge:" in yaml_text
    assert gap.scenario_id in yaml_text
    assert str(sample_action_ir.action_id) in yaml_text


def test_4_valid_sigma_yaml_accepted(sample_action_ir):
    """4. Valid Sigma YAML parsed and accepted."""
    rule = CandidateSigmaRule(
        rule_id=str(uuid4()),
        title="Detect Shadow Access",
        description="Detects reading /etc/shadow",
        technique_id="T1003.008",
        logsource={"category": "process_creation", "product": "linux"},
        detection={"selection": {"CommandLine|contains": "shadow"}, "condition": "selection"},
        source_scenario_id=str(uuid4()),
        source_action_ids=[str(sample_action_ir.action_id)],
    )

    parsed = SigmaRuleValidator.validate_yaml(rule.to_yaml())
    assert parsed["title"] == "Detect Shadow Access"
    assert "x-sentinelforge" in parsed


def test_5_malformed_yaml_rejected():
    """5. Malformed YAML string rejected."""
    bad_yaml = "title: [unclosed list"
    with pytest.raises(ValueError, match="Malformed YAML syntax"):
        SigmaRuleValidator.validate_yaml(bad_yaml)


def test_6_missing_required_fields_rejected():
    """6. Missing required Sigma fields rejected."""
    incomplete_yaml = """
title: Test Rule
id: 1234
# missing logsource and detection
x-sentinelforge:
  scenario_id: sc-1
  action_ids: [act-1]
  technique_id: T1003.008
  rule_id: 1234
"""
    with pytest.raises(ValueError, match="Missing required Sigma field"):
        SigmaRuleValidator.validate_yaml(incomplete_yaml)


def test_7_candidate_detects_malicious_telemetry(sample_action_ir, sample_malicious_event, sample_benign_events):
    """7. Candidate rule detects target malicious telemetry."""
    analyst = BlueAgentAnalyst()
    sandbox = RuleValidationSandbox()
    gap = GapAnalysisResult(
        scenario_id=str(uuid4()),
        action_id=str(sample_action_ir.action_id),
        technique_id="T1003.008",
        original_outcome="DETECTION_GAP",
        root_cause="NO_TELEMETRY",
        reason="No telemetry",
    )
    rule = analyst.propose_candidate_rule(gap, action=sample_action_ir, telemetry_events=[sample_malicious_event])

    res = sandbox.validate_candidate_rule(rule, [sample_malicious_event], sample_benign_events)
    assert res.status == ValidationSandboxStatus.ACCEPTED
    assert res.malicious_passed is True
    assert res.benign_passed is True


def test_8_candidate_ignores_benign_telemetry(sample_action_ir, sample_malicious_event, sample_benign_events):
    """8. Candidate rule does not trigger on benign telemetry."""
    analyst = BlueAgentAnalyst()
    sandbox = RuleValidationSandbox()
    gap = GapAnalysisResult(
        scenario_id=str(uuid4()),
        action_id=str(sample_action_ir.action_id),
        technique_id="T1003.008",
        original_outcome="DETECTION_GAP",
        root_cause="NO_TELEMETRY",
        reason="No telemetry",
    )
    rule = analyst.propose_candidate_rule(gap, action=sample_action_ir, telemetry_events=[sample_malicious_event])

    res = sandbox.validate_candidate_rule(rule, [sample_malicious_event], sample_benign_events)
    assert res.benign_passed is True


def test_9_overly_broad_rule_rejected(sample_action_ir, sample_malicious_event, sample_benign_events):
    """9. Overly broad rule (bare process_name=bash) rejected."""
    broad_rule = CandidateSigmaRule(
        rule_id=str(uuid4()),
        title="Broad Bash Match",
        description="Matches all bash processes",
        technique_id="T1059.004",
        logsource={"category": "process_creation", "product": "linux"},
        detection={"selection": {"ProcessName": "bash"}, "condition": "selection"},
        source_scenario_id=str(uuid4()),
        source_action_ids=[str(sample_action_ir.action_id)],
    )

    sandbox = RuleValidationSandbox()
    res = sandbox.validate_candidate_rule(broad_rule, [sample_malicious_event], sample_benign_events)
    assert res.status == ValidationSandboxStatus.REJECTED
    assert "Overly broad rule rejected" in res.reason


def test_10_technique_mismatch_rejected(sample_action_ir, sample_malicious_event, sample_benign_events):
    """10. Candidate rule technique mismatch with expected gap action technique rejected."""
    mismatched_rule = CandidateSigmaRule(
        rule_id=str(uuid4()),
        title="Wrong Technique Rule",
        description="Rule with mismatched technique",
        technique_id="T1059.004",  # Action expects T1003.008
        logsource={"category": "process_creation", "product": "linux"},
        detection={"selection": {"CommandLine|contains": "shadow"}, "condition": "selection"},
        source_scenario_id=str(uuid4()),
        source_action_ids=[str(sample_action_ir.action_id)],
    )

    sandbox = RuleValidationSandbox()
    res = sandbox.validate_candidate_rule(
        mismatched_rule, [sample_malicious_event], sample_benign_events, expected_technique="T1003.008"
    )
    assert res.status == ValidationSandboxStatus.REJECTED
    assert "Technique mismatch" in res.reason


def test_11_blue_agent_has_no_command_execution_capability():
    """11. Verify BlueAgent components have no command execution capability."""
    analyst = BlueAgentAnalyst()
    sandbox = RuleValidationSandbox()
    validator = SigmaRuleValidator()

    for obj in (analyst, sandbox, validator):
        assert not hasattr(obj, "execute")
        assert not hasattr(obj, "run_command")
        assert not hasattr(obj, "system")


def test_12_blue_agent_cannot_create_signed_blueprint():
    """12. Verify BlueAgent components cannot generate SignedBlueprints."""
    analyst = BlueAgentAnalyst()
    sandbox = RuleValidationSandbox()

    for obj in (analyst, sandbox):
        assert not hasattr(obj, "sign_blueprint")
        assert not hasattr(obj, "create_signed_blueprint")


def test_13_provenance_survives_serialization(sample_action_ir):
    """13. Provenance survives YAML serialization and deserialization."""
    original_rule = CandidateSigmaRule(
        rule_id=str(uuid4()),
        title="Provenance Test Rule",
        description="Testing serialization of x-sentinelforge block",
        technique_id="T1003.008",
        logsource={"category": "process_creation", "product": "linux"},
        detection={"selection": {"TargetFile|contains": "/etc/shadow"}, "condition": "selection"},
        source_scenario_id=str(uuid4()),
        source_action_ids=[str(sample_action_ir.action_id)],
    )

    yaml_text = original_rule.to_yaml()
    reconstructed = CandidateSigmaRule.from_yaml(yaml_text)

    assert reconstructed.rule_id == original_rule.rule_id
    assert reconstructed.source_scenario_id == original_rule.source_scenario_id
    assert reconstructed.source_action_ids == original_rule.source_action_ids
    assert reconstructed.technique_id == original_rule.technique_id


def test_14_multiple_detection_gaps_handled(sample_action_ir):
    """14. Multiple detection gaps within a scenario correctly analyzed."""
    action2 = ActionIR(
        action_id=uuid4(),
        blueprint_id=uuid4(),
        technique_id="T1070.004",
        action_type=ActionType.PROCESS_EXEC,
        target="sentinelforge-target",
        run_as_user="labuser",
        executable="/usr/bin/bash",
        arguments=["-c", "rm /tmp/evidence.log"],
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc) + timedelta(minutes=5),
    )

    scen_outcome = ScenarioDetectionOutcome(
        scenario_id=str(uuid4()),
        organization_id=str(uuid4()),
        overall_outcome=DetectionOutcome.DETECTION_GAP,
        action_outcomes=[
            ActionDetectionOutcome(
                action_id=str(sample_action_ir.action_id),
                technique_id="T1003.008",
                outcome=DetectionOutcome.DETECTION_GAP,
                reason="No telemetry captured",
            ),
            ActionDetectionOutcome(
                action_id=str(action2.action_id),
                technique_id="T1070.004",
                outcome=DetectionOutcome.NOT_DETECTED,
                evidence_event_ids=["ev-2"],
                reason="Telemetry captured but no rule matched",
            ),
        ],
        gap_action_ids=[str(sample_action_ir.action_id), str(action2.action_id)],
    )

    analyst = BlueAgentAnalyst()
    gaps = analyst.analyze_gap(scen_outcome, actions=[sample_action_ir, action2])
    assert len(gaps) == 2
    assert gaps[0].technique_id == "T1003.008"
    assert gaps[1].technique_id == "T1070.004"


def test_15_failed_validation_cannot_create_retest_request(sample_action_ir):
    """15. Rejected candidate rule cannot create a RetestRequest."""
    rule = CandidateSigmaRule(
        rule_id=str(uuid4()),
        title="Invalid Rule",
        description="Rule with failed validation",
        technique_id="T1003.008",
        source_scenario_id=str(uuid4()),
        source_action_ids=[str(sample_action_ir.action_id)],
    )
    rej_val = ValidationSandboxResult(
        rule_id=rule.rule_id,
        status=ValidationSandboxStatus.REJECTED,
        malicious_passed=False,
        benign_passed=True,
        reason="Malicious detection failed",
    )

    orchestrator = RetestOrchestrator()
    with pytest.raises(ValueError, match="Cannot prepare RetestRequest for candidate rule"):
        orchestrator.prepare_retest(
            scenario_id=rule.source_scenario_id,
            gap_action_ids=rule.source_action_ids,
            candidate_rules=[rule],
            validation_result=rej_val,
        )


def test_16_validated_rule_creates_retest_request(sample_action_ir):
    """16. ACCEPTED candidate rule creates valid RetestRequest."""
    rule = CandidateSigmaRule(
        rule_id=str(uuid4()),
        title="Valid Rule",
        description="Validated rule",
        technique_id="T1003.008",
        logsource={"category": "process_creation", "product": "linux"},
        detection={"selection": {"CommandLine|contains": "shadow"}, "condition": "selection"},
        source_scenario_id=str(uuid4()),
        source_action_ids=[str(sample_action_ir.action_id)],
    )
    acc_val = ValidationSandboxResult(
        rule_id=rule.rule_id,
        status=ValidationSandboxStatus.ACCEPTED,
        malicious_passed=True,
        benign_passed=True,
        reason="Validation passed",
    )

    orchestrator = RetestOrchestrator()
    req = orchestrator.prepare_retest(
        scenario_id=rule.source_scenario_id,
        gap_action_ids=rule.source_action_ids,
        candidate_rules=[rule],
        validation_result=acc_val,
    )

    assert isinstance(req, RetestRequest)
    assert req.candidate_rules[0].rule_id == rule.rule_id


def test_17_retest_result_before_after_tracking(mock_objective, sample_action_ir):
    """17. RetestResult correctly records before and after detection states."""
    scen_id = uuid4()
    res = RetestResult(
        retest_id=uuid4(),
        organization_id=mock_objective.organization_id,
        scenario_id=scen_id,
        before_outcome="DETECTION_GAP",
        after_outcome="DETECTED",
        detection_improved=True,
        validated_rule_ids=["rule-123"],
    )

    assert res.before_outcome == "DETECTION_GAP"
    assert res.after_outcome == "DETECTED"
    assert res.detection_improved is True


def test_18_gap_evaluator_consumes_retest_telemetry(sample_action_ir, sample_malicious_event):
    """18. DetectionGapEvaluator accurately evaluates telemetry from retest."""
    evaluator = DetectionGapEvaluator()
    sigma = SigmaEngine()

    rule_yaml = f"""
title: Retest Detection Rule
id: {sample_action_ir.action_id}
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    CommandLine|contains: 'shadow'
  condition: selection
x-sentinelforge:
  scenario_id: '{sample_malicious_event.correlation_id}'
  action_ids: ['{sample_action_ir.action_id}']
  technique_id: 'T1003.008'
  rule_id: 'rule-retest-1'
"""
    sigma.load_rule_from_yaml(rule_yaml, "rule-retest-1", "T1003.008")

    outcome = evaluator.evaluate_scenario(
        scenario_id=sample_malicious_event.correlation_id,
        actions=[sample_action_ir],
        events=[sample_malicious_event],
        sigma_engine=sigma,
    )

    assert outcome.overall_outcome == DetectionOutcome.DETECTED
    assert outcome.action_outcomes[0].matched_rule_ids == ["rule-retest-1"]


def test_19_complete_remediation_loop_success(mock_objective, sample_action_ir, sample_malicious_event, sample_benign_events):
    """19. Complete closed-loop remediation flow: DETECTION_GAP -> Blue Agent -> candidate rule -> sandbox -> retest -> DETECTED -> detection_improved=True."""
    # Step A: Initial scenario run resulting in DETECTION_GAP
    before_scen_outcome = ScenarioDetectionOutcome(
        scenario_id=str(uuid4()),
        organization_id=str(mock_objective.organization_id),
        overall_outcome=DetectionOutcome.DETECTION_GAP,
        action_outcomes=[
            ActionDetectionOutcome(
                action_id=str(sample_action_ir.action_id),
                technique_id="T1003.008",
                outcome=DetectionOutcome.DETECTION_GAP,
                reason="No detection rules configured",
            )
        ],
        gap_action_ids=[str(sample_action_ir.action_id)],
    )

    # Step B: Blue Agent Analyst consumes gap
    analyst = BlueAgentAnalyst()
    gaps = analyst.analyze_gap(before_scen_outcome, actions=[sample_action_ir])
    assert len(gaps) == 1

    # Step C: Propose Candidate Sigma Rule
    candidate = analyst.propose_candidate_rule(gaps[0], action=sample_action_ir, telemetry_events=[sample_malicious_event])

    # Step D: Validation Sandbox
    sandbox = RuleValidationSandbox()
    sandbox_res = sandbox.validate_candidate_rule(candidate, [sample_malicious_event], sample_benign_events)
    assert sandbox_res.status == ValidationSandboxStatus.ACCEPTED

    # Step E: Retest Orchestrator prepares RetestRequest
    orchestrator = RetestOrchestrator()
    retest_req = orchestrator.prepare_retest(
        scenario_id=before_scen_outcome.scenario_id,
        gap_action_ids=before_scen_outcome.gap_action_ids,
        candidate_rules=[candidate],
        validation_result=sandbox_res,
    )

    # Step F: Authorized Execution Retest
    red_planner = RedAgentPlanner()
    adapter = MockAdapter()
    sigma = SigmaEngine()
    evaluator = DetectionGapEvaluator()

    retest_res = orchestrator.execute_retest(
        retest_request=retest_req,
        objective=mock_objective,
        red_planner=red_planner,
        adapter=adapter,
        sigma_engine=sigma,
        gap_evaluator=evaluator,
        before_outcome=before_scen_outcome,
        strategy_type="credential_dump_shadow",
    )

    assert retest_res.before_outcome in ("DETECTION_GAP", "NOT_DETECTED")
    assert retest_res.after_outcome == "DETECTED"
    assert retest_res.detection_improved is True
    assert candidate.rule_id in retest_res.validated_rule_ids

    # Step G: State machine transition to VERIFIED
    new_state = ExerciseStateMachine.transition("RETESTING", "VERIFIED", retest_result=retest_res)
    assert new_state == "VERIFIED"


def test_20_verified_state_requires_valid_retest_result(mock_objective):
    """20. ExerciseStateMachine VERIFIED requires valid RetestResult and rejects invalid / missing / bare boolean attempts."""
    # Missing retest_result -> REJECTED
    with pytest.raises(SecurityRejection) as exc1:
        ExerciseStateMachine.transition("RETESTING", "VERIFIED", has_retest_result=False)
    assert exc1.value.code == SecurityRejectionCode.VERIFICATION_FAILED

    # Bare boolean True -> REJECTED
    with pytest.raises(SecurityRejection) as exc2:
        ExerciseStateMachine.transition("RETESTING", "VERIFIED", has_retest_result=True)
    assert exc2.value.code == SecurityRejectionCode.VERIFICATION_FAILED

    # RetestResult with before=DETECTED -> REJECTED
    invalid_before = RetestResult(
        retest_id=uuid4(),
        organization_id=mock_objective.organization_id,
        scenario_id=uuid4(),
        before_outcome="DETECTED",
        after_outcome="DETECTED",
        detection_improved=True,
    )
    with pytest.raises(SecurityRejection) as exc3:
        ExerciseStateMachine.transition("RETESTING", "VERIFIED", retest_result=invalid_before)
    assert exc3.value.code == SecurityRejectionCode.VERIFICATION_FAILED

    # RetestResult with after!=DETECTED -> REJECTED
    invalid_after = RetestResult(
        retest_id=uuid4(),
        organization_id=mock_objective.organization_id,
        scenario_id=uuid4(),
        before_outcome="DETECTION_GAP",
        after_outcome="NOT_DETECTED",
        detection_improved=False,
    )
    with pytest.raises(SecurityRejection) as exc4:
        ExerciseStateMachine.transition("RETESTING", "VERIFIED", retest_result=invalid_after)
    assert exc4.value.code == SecurityRejectionCode.VERIFICATION_FAILED

    # RetestResult with detection_improved=False -> REJECTED
    invalid_improved = RetestResult(
        retest_id=uuid4(),
        organization_id=mock_objective.organization_id,
        scenario_id=uuid4(),
        before_outcome="DETECTION_GAP",
        after_outcome="DETECTED",
        detection_improved=False,
    )
    with pytest.raises(SecurityRejection) as exc5:
        ExerciseStateMachine.transition("RETESTING", "VERIFIED", retest_result=invalid_improved)
    assert exc5.value.code == SecurityRejectionCode.VERIFICATION_FAILED

    # Valid RetestResult -> ACCEPTED
    valid_res = RetestResult(
        retest_id=uuid4(),
        organization_id=mock_objective.organization_id,
        scenario_id=uuid4(),
        before_outcome="DETECTION_GAP",
        after_outcome="DETECTED",
        detection_improved=True,
    )
    assert ExerciseStateMachine.transition("RETESTING", "VERIFIED", retest_result=valid_res) == "VERIFIED"


def test_21_adversarial_blue_agent_inputs(sample_action_ir, sample_malicious_event, sample_benign_events):
    """21. Adversarial Blue Agent inputs (malformed YAML, missing provenance, code injection attempts) fail safely."""
    sandbox = RuleValidationSandbox()

    # A. Missing x-sentinelforge provenance
    no_prov_rule = CandidateSigmaRule(
        rule_id=str(uuid4()),
        title="No Provenance Rule",
        description="Missing provenance fields",
        technique_id="T1003.008",
        logsource={"category": "process_creation", "product": "linux"},
        detection={"selection": {"CommandLine|contains": "shadow"}, "condition": "selection"},
        source_scenario_id="",  # Empty!
        source_action_ids=[],    # Empty!
    )
    res_no_prov = sandbox.validate_candidate_rule(no_prov_rule, [sample_malicious_event], sample_benign_events)
    assert res_no_prov.status == ValidationSandboxStatus.REJECTED
    assert "Missing provenance" in res_no_prov.reason

    # B. Attempted YAML injection / malformed structure
    malicious_yaml = """
title: Injection Attempt
id: 1234
logsource:
  category: process_creation
  product: linux
detection: !!python/object/apply:os.system ['echo hacked']
x-sentinelforge:
  scenario_id: sc-1
  action_ids: [act-1]
  technique_id: T1003.008
  rule_id: 1234
"""
    with pytest.raises(ValueError):
        SigmaRuleValidator.validate_yaml(malicious_yaml)
