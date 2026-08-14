"""
SentinelForge Phase 3/4/5 Bridge — DetectionGapEvaluator Unit Tests

Verifies deterministic, scenario-level detection correlation, isolation,
deduplication, technique matching, false-positive protection, and security invariants.
"""

from datetime import datetime, timedelta, timezone
import json
import os
from uuid import uuid4
import pytest

from sentinelforge.domain.action_ir import ActionIR, ActionType
from sentinelforge.domain.blueprint import SignedBlueprint
from sentinelforge.domain.experiment import RiskLevel
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary
from sentinelforge.policy.engine import PolicyEngine
from sentinelforge.detection.normalizer import TelemetryNormalizer, NormalizedEvent
from sentinelforge.detection.sigma_engine import SigmaEngine, DetectionOutcome
from sentinelforge.detection.evaluator import (
    DetectionGapEvaluator,
    ActionDetectionOutcome,
    ScenarioDetectionOutcome,
)

RULES_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "src", "sentinelforge", "detection", "rules"
)

FALCO_SHELL_JSON = json.dumps({
    "time": "2026-08-14T10:00:00Z",
    "rule": "SentinelForge Telemetry Syscalls",
    "priority": "WARNING",
    "output": "Syscall event in target container",
    "output_fields": {
        "evt.type": "execve",
        "evt.hostname": "sentinelforge-host",
        "container.id": "abc123container",
        "container.name": "sentinelforge-target",
        "proc.name": "bash",
        "proc.exe": "/usr/bin/bash",
        "proc.cmdline": "bash -c whoami",
        "user.name": "labuser",
        "user.uid": 1000,
        "fd.name": ""
    }
})

FALCO_SHADOW_JSON = json.dumps({
    "time": "2026-08-14T10:05:00Z",
    "rule": "SentinelForge Telemetry Syscalls",
    "priority": "WARNING",
    "output": "Shadow access attempt",
    "output_fields": {
        "evt.type": "openat",
        "evt.hostname": "sentinelforge-host",
        "container.id": "abc123container",
        "container.name": "sentinelforge-target",
        "proc.name": "cat",
        "proc.exe": "/usr/bin/cat",
        "proc.cmdline": "cat /etc/shadow",
        "user.name": "labuser",
        "user.uid": 1000,
        "fd.name": "/etc/shadow"
    }
})


@pytest.fixture
def loaded_sigma_engine():
    engine = SigmaEngine()
    engine.load_rules_from_directory(RULES_DIR)
    return engine


@pytest.fixture
def normalizer():
    return TelemetryNormalizer()


@pytest.fixture
def sample_action_whoami():
    now = datetime.now(timezone.utc)
    return ActionIR(
        action_id=uuid4(),
        blueprint_id=uuid4(),
        technique_id="T1059.004",
        action_type=ActionType.PROCESS_EXEC,
        target="sentinelforge-target",
        executable="/usr/bin/bash",
        arguments=["-c", "whoami"],
        run_as_user="labuser",
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
    )


@pytest.fixture
def sample_action_shadow():
    now = datetime.now(timezone.utc)
    return ActionIR(
        action_id=uuid4(),
        blueprint_id=uuid4(),
        technique_id="T1003.008",
        action_type=ActionType.PROCESS_EXEC,
        target="sentinelforge-target",
        executable="/usr/bin/bash",
        arguments=["-c", "cat /etc/shadow"],
        run_as_user="labuser",
        issued_at=now,
        expires_at=now + timedelta(seconds=30),
    )


class TestDetectionGapEvaluator:
    evaluator = DetectionGapEvaluator()

    def test_1_single_action_matching_sigma_detection(self, normalizer, loaded_sigma_engine, sample_action_whoami):
        ev = normalizer.normalize(FALCO_SHELL_JSON)
        res = self.evaluator.evaluate_action(sample_action_whoami, [ev], loaded_sigma_engine)

        assert res.outcome == DetectionOutcome.DETECTED
        assert "sentinelforge-shell-execution" in res.matched_rule_ids
        assert ev.event_id in res.evidence_event_ids

    def test_2_single_action_no_matching_detection(self, normalizer, sample_action_whoami):
        empty_engine = SigmaEngine()
        ev = normalizer.normalize(FALCO_SHELL_JSON)
        res = self.evaluator.evaluate_action(sample_action_whoami, [ev], empty_engine)

        assert res.outcome == DetectionOutcome.NOT_DETECTED
        assert res.matched_rule_ids == []
        assert "no Sigma rule matched" in res.reason

    def test_3_telemetry_exists_unrelated_sigma_rule_matches(self, normalizer, sample_action_whoami):
        # Engine loaded with a rule that matches shell execution but specifies an unrelated technique ID (T1003.008)
        engine = SigmaEngine()
        yaml_rule = """
title: Unrelated Rule Match
id: rule-unrelated-tech
detection:
    selection:
        ProcessName: bash
    condition: selection
x-sentinelforge:
    rule_id: rule-unrelated-tech
    technique_id: T1003.008
"""
        engine.load_rule_from_yaml(yaml_rule, "rule-unrelated-tech", "T1003.008")
        shell_ev = normalizer.normalize(FALCO_SHELL_JSON)

        res = self.evaluator.evaluate_action(sample_action_whoami, [shell_ev], engine)

        assert res.outcome == DetectionOutcome.NOT_DETECTED
        assert res.matched_rule_ids == []
        assert "unrelated rule" in res.reason

    def test_3b_unrelated_telemetry_yields_detection_gap(self, normalizer, loaded_sigma_engine, sample_action_whoami):
        # Falco event is for shadow access, but evaluated action is whoami
        shadow_ev = normalizer.normalize(FALCO_SHADOW_JSON)
        res = self.evaluator.evaluate_action(sample_action_whoami, [shadow_ev], loaded_sigma_engine)

        assert res.outcome == DetectionOutcome.DETECTION_GAP
        assert "No relevant telemetry" in res.reason


    def test_4_multi_action_scenario_one_detected_one_missed(self, normalizer, loaded_sigma_engine, sample_action_whoami, sample_action_shadow):
        scenario_id = uuid4()
        # Telemetry only includes whoami (shell execution), shadow access telemetry is missing
        shell_ev = normalizer.normalize(FALCO_SHELL_JSON)
        shell_ev.correlation_id = str(scenario_id)

        scen_outcome = self.evaluator.evaluate_scenario(
            scenario_id=scenario_id,
            actions=[sample_action_whoami, sample_action_shadow],
            events=[shell_ev],
            sigma_engine=loaded_sigma_engine,
        )

        assert scen_outcome.overall_outcome == DetectionOutcome.DETECTION_GAP
        assert str(sample_action_shadow.action_id) in scen_outcome.gap_action_ids
        assert str(sample_action_whoami.action_id) not in scen_outcome.gap_action_ids
        assert len(scen_outcome.action_outcomes) == 2

    def test_5_multi_action_scenario_all_detected(self, normalizer, loaded_sigma_engine, sample_action_whoami, sample_action_shadow):
        scenario_id = uuid4()
        shell_ev = normalizer.normalize(FALCO_SHELL_JSON)
        shell_ev.correlation_id = str(scenario_id)
        shadow_ev = normalizer.normalize(FALCO_SHADOW_JSON)
        shadow_ev.correlation_id = str(scenario_id)

        scen_outcome = self.evaluator.evaluate_scenario(
            scenario_id=scenario_id,
            actions=[sample_action_whoami, sample_action_shadow],
            events=[shell_ev, shadow_ev],
            sigma_engine=loaded_sigma_engine,
        )

        assert scen_outcome.overall_outcome == DetectionOutcome.DETECTED
        assert scen_outcome.gap_action_ids == []
        assert all(ao.outcome == DetectionOutcome.DETECTED for ao in scen_outcome.action_outcomes)

    def test_6_no_telemetry_for_executed_action(self, loaded_sigma_engine, sample_action_whoami):
        res = self.evaluator.evaluate_action(sample_action_whoami, [], loaded_sigma_engine)

        assert res.outcome == DetectionOutcome.DETECTION_GAP
        assert "No relevant telemetry events captured" in res.reason

    def test_7_technique_id_mismatch(self, normalizer, sample_action_whoami):
        # Engine with custom rule matching T1033 instead of expected T1059.004
        engine = SigmaEngine()
        yaml_rule = """
title: User Discovery Rule
id: rule-user-discovery
detection:
    selection:
        ProcessName: bash
    condition: selection
x-sentinelforge:
    rule_id: rule-user-discovery
    technique_id: T1033
"""
        engine.load_rule_from_yaml(yaml_rule, "rule-user-discovery", "T1033")
        shell_ev = normalizer.normalize(FALCO_SHELL_JSON)

        res = self.evaluator.evaluate_action(sample_action_whoami, [shell_ev], engine)
        assert res.outcome == DetectionOutcome.NOT_DETECTED
        assert res.matched_rule_ids == []

    def test_8_scenario_identity_mismatch(self, normalizer, loaded_sigma_engine, sample_action_whoami):
        target_scenario_id = uuid4()
        other_scenario_id = uuid4()

        # Telemetry belongs to other scenario
        ev = normalizer.normalize(FALCO_SHELL_JSON)
        ev.correlation_id = str(other_scenario_id)

        res = self.evaluator.evaluate_action(
            sample_action_whoami, [ev], loaded_sigma_engine, correlation_id=str(target_scenario_id)
        )

        assert res.outcome == DetectionOutcome.DETECTION_GAP
        assert "No relevant telemetry" in res.reason

    def test_9_duplicate_telemetry_events(self, normalizer, loaded_sigma_engine, sample_action_whoami):
        ev = normalizer.normalize(FALCO_SHELL_JSON)
        duplicate_events = [ev, ev, ev]

        res = self.evaluator.evaluate_action(sample_action_whoami, duplicate_events, loaded_sigma_engine)

        assert res.outcome == DetectionOutcome.DETECTED
        assert len(res.evidence_event_ids) == 1
        assert res.evidence_event_ids[0] == ev.event_id

    def test_10_malformed_incomplete_telemetry(self, normalizer, loaded_sigma_engine, sample_action_whoami):
        bad_events = [None, "invalid_str", {"bad": "dict"}]
        res = self.evaluator.evaluate_action(sample_action_whoami, bad_events, loaded_sigma_engine)

        assert res.outcome == DetectionOutcome.DETECTION_GAP
        assert "No relevant telemetry" in res.reason

    def test_11_multiple_sigma_rules_match_same_action(self, normalizer, sample_action_whoami):
        engine = SigmaEngine()
        yaml_rule1 = """
title: Rule 1
id: rule-shell-1
detection:
    selection:
        ProcessName: bash
    condition: selection
x-sentinelforge:
    rule_id: rule-shell-1
    technique_id: T1059.004
"""
        yaml_rule2 = """
title: Rule 2
id: rule-shell-2
detection:
    selection:
        CommandLine|contains: whoami
    condition: selection
x-sentinelforge:
    rule_id: rule-shell-2
    technique_id: T1059.004
"""
        engine.load_rule_from_yaml(yaml_rule1, "rule-shell-1", "T1059.004")
        engine.load_rule_from_yaml(yaml_rule2, "rule-shell-2", "T1059.004")

        shell_ev = normalizer.normalize(FALCO_SHELL_JSON)
        res = self.evaluator.evaluate_action(sample_action_whoami, [shell_ev], engine)

        assert res.outcome == DetectionOutcome.DETECTED
        assert "rule-shell-1" in res.matched_rule_ids
        assert "rule-shell-2" in res.matched_rule_ids

    def test_12_partial_telemetry_without_technique_evidence(self, sample_action_whoami):
        # Normalized event with ProcessName bash, but no rules matched
        ev = NormalizedEvent(
            event_id="test-ev-1",
            correlation_id=None,
            timestamp="2026-08-14T10:00:00Z",
            source="falco",
            EventType="execve",
            ProcessName="bash",
            Executable="/usr/bin/bash",
            CommandLine="bash -c whoami",
            UserName="labuser",
            UserUid=1000,
            TargetFile=None,
            ContainerName="sentinelforge-target",
            ContainerId="c1",
            ParentProcess=None,
            raw_event_hash="hash1",
        )
        empty_engine = SigmaEngine()
        res = self.evaluator.evaluate_action(sample_action_whoami, [ev], empty_engine)

        assert res.outcome == DetectionOutcome.NOT_DETECTED
        assert res.matched_rule_ids == []

    def test_13_empty_action_list(self, loaded_sigma_engine):
        scen_outcome = self.evaluator.evaluate_scenario(
            scenario_id=uuid4(),
            actions=[],
            events=[],
            sigma_engine=loaded_sigma_engine,
        )

        assert scen_outcome.overall_outcome == DetectionOutcome.DETECTION_GAP
        assert scen_outcome.gap_action_ids == []
        assert "No executed actions provided" in scen_outcome.reason

    def test_14_mixed_valid_and_malformed_telemetry(self, normalizer, loaded_sigma_engine, sample_action_whoami):
        shell_ev = normalizer.normalize(FALCO_SHELL_JSON)
        mixed = [None, shell_ev, "junk"]

        res = self.evaluator.evaluate_action(sample_action_whoami, mixed, loaded_sigma_engine)

        assert res.outcome == DetectionOutcome.DETECTED
        assert "sentinelforge-shell-execution" in res.matched_rule_ids

    def test_15_outcome_serialization(self, normalizer, loaded_sigma_engine, sample_action_whoami, sample_action_shadow):
        scenario_id = uuid4()
        shell_ev = normalizer.normalize(FALCO_SHELL_JSON)
        shell_ev.correlation_id = str(scenario_id)

        scen_outcome = self.evaluator.evaluate_scenario(
            scenario_id=scenario_id,
            actions=[sample_action_whoami, sample_action_shadow],
            events=[shell_ev],
            sigma_engine=loaded_sigma_engine,
        )

        outcome_dict = scen_outcome.to_dict()
        assert outcome_dict["scenario_id"] == str(scenario_id)
        assert outcome_dict["overall_outcome"] == "DETECTION_GAP"
        assert len(outcome_dict["action_outcomes"]) == 2
        assert str(sample_action_shadow.action_id) in outcome_dict["gap_action_ids"]

        json_str = scen_outcome.to_json()
        assert isinstance(json_str, str)
        parsed = json.loads(json_str)
        assert parsed["scenario_id"] == str(scenario_id)

    def test_16_critical_security_read_only_invariant(self, sample_action_whoami):
        """Proves DetectionGapEvaluator is strictly analytical and read-only."""
        evaluator = DetectionGapEvaluator()
        
        # Verify evaluator has no execution methods
        assert not hasattr(evaluator, "execute")
        assert not hasattr(evaluator, "run_command")
        assert not hasattr(evaluator, "sign_blueprint")
        assert not hasattr(evaluator, "authorize")

        # Verify ActionIR and fields remain unmodified during evaluation
        orig_action_dict = sample_action_whoami.model_dump()
        evaluator.evaluate_action(sample_action_whoami, [], SigmaEngine())
        assert sample_action_whoami.model_dump() == orig_action_dict
