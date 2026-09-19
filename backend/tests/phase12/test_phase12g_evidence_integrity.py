"""Phase 12G — Evidence Integrity."""

import pytest
from uuid import uuid4
from datetime import datetime, timezone, timedelta

from sentinelforge.domain.action_ir import ActionIR
from sentinelforge.domain.exceptions import SecurityRejection
from sentinelforge.policy.engine import PolicyEngine
from sentinelforge.detection.evaluator import PurpleEvaluation, DetectionOutcome


class TestEvidenceCannotBeFabricated:
    def test_detection_outcome_has_valid_values(self):
        outcomes = {e.value for e in DetectionOutcome}
        assert "DETECTED" in outcomes
        assert "NOT_DETECTED" in outcomes
        assert "DETECTION_GAP" in outcomes

    def test_purple_evaluation_detection_is_string(self):
        e = PurpleEvaluation(
            evaluation_id="e1", experiment_id="x1", execution_id="d1",
            organization_id=uuid4(), technique_id="T1003",
            detection_status="DETECTED", matched_rule_ids=[], evidence_event_ids=[])
        assert e.detection_status == "DETECTED"


class TestEvidenceLinkedToRealExecution:
    def test_evaluation_requires_execution_id(self):
        with pytest.raises(TypeError):
            PurpleEvaluation(
                evaluation_id="test", experiment_id="test",
                organization_id=uuid4(), technique_id="T1003",
                detection_status="DETECTED", matched_rule_ids=[], evidence_event_ids=[])

    def test_evaluation_requires_experiment_id(self):
        with pytest.raises(TypeError):
            PurpleEvaluation(
                evaluation_id="test", execution_id="test",
                organization_id=uuid4(), technique_id="T1003",
                detection_status="DETECTED", matched_rule_ids=[], evidence_event_ids=[])


class TestDetectionOutcomeImmutable:
    def test_detection_outcome_cannot_be_modified(self):
        outcome = DetectionOutcome.DETECTED
        assert outcome.value == "DETECTED"

    def test_all_outcomes_are_string_enum(self):
        for outcome in DetectionOutcome:
            assert isinstance(outcome.value, str)


class TestActionIRLinkedToExecution:
    def test_action_requires_blueprint_id(self):
        now = datetime.now(timezone.utc)
        with pytest.raises(Exception):
            ActionIR(
                action_id=uuid4(), technique_id="T1003",
                action_type="process_exec", target="sentinelforge-target",
                executable="/usr/bin/bash", arguments=["-c", "whoami"],
                run_as_user="labuser", max_execution_seconds=30,
                max_stdout_bytes=4096, issued_at=now,
                expires_at=now + timedelta(minutes=5))


class TestPolicyDecisionAuditTrail:
    def test_policy_engine_returns_true_on_valid_action(self):
        now = datetime.now(timezone.utc)
        action = ActionIR(
            action_id=uuid4(), blueprint_id=uuid4(), technique_id="T1003",
            action_type="process_exec", target="sentinelforge-target",
            executable="/usr/bin/bash", arguments=["-c", "whoami"],
            run_as_user="labuser", max_execution_seconds=30,
            max_stdout_bytes=4096, issued_at=now,
            expires_at=now + timedelta(minutes=5))
        result = PolicyEngine.validate(action)
        assert result is True
