"""Phase 12C — False Mitigation Attacks.

Attempt to force MITIGATED without actual improvement.

MITIGATED MUST NEVER OCCUR unless:
- before_outcome is DETECTION_GAP or NOT_DETECTED
- after_outcome is DETECTED
- detection_improved is True
- State is COMPARING
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone, timedelta

from sentinelforge.domain.state_machine import CyberImmuneStateMachine
from sentinelforge.domain.exceptions import SecurityRejection, SecurityRejectionCode
from sentinelforge.defensive.before_after_comparison import (
    BeforeAfterComparison,
    BeforeAfterCoverage,
)
from sentinelforge.detection.evaluator import DetectionOutcome, PurpleEvaluation


class TestFalseMitigationAttacks:
    def test_llm_claim_alone_cannot_produce_mitigated(self):
        """Even if LLM claims defense worked, state machine requires evidence."""
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING",
                "MITIGATED",
                before_outcome="DETECTION_GAP",
                after_outcome="DETECTION_GAP",
                detection_improved=False,
            )

    def test_proposal_says_detection_will_improve(self):
        """Proposal claiming improvement but retest doesn't confirm it."""
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING",
                "MITIGATED",
                before_outcome="NOT_DETECTED",
                after_outcome="NOT_DETECTED",
                detection_improved=False,
            )

    def test_defense_test_succeeds_but_retest_does_not_improve(self):
        """Defense test passed but actual retest shows no improvement."""
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING",
                "MITIGATED",
                before_outcome="DETECTION_GAP",
                after_outcome="DETECTION_GAP",
                detection_improved=True,
            )

    def test_before_after_data_incomplete(self):
        """Missing before/after data cannot produce MITIGATED."""
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING",
                "MITIGATED",
                before_outcome="",
                after_outcome="DETECTED",
                detection_improved=True,
            )

    def test_after_outcome_not_detected(self):
        """After outcome is NOT_DETECTED, not DETECTED."""
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING",
                "MITIGATED",
                before_outcome="NOT_DETECTED",
                after_outcome="NOT_DETECTED",
                detection_improved=True,
            )

    def test_detection_improved_false(self):
        """detection_improved=False blocks MITIGATED."""
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING",
                "MITIGATED",
                before_outcome="NOT_DETECTED",
                after_outcome="DETECTED",
                detection_improved=False,
            )

    def test_before_outcome_was_already_detected(self):
        """If before was already DETECTED, cannot claim MITIGATED."""
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING",
                "MITIGATED",
                before_outcome="DETECTED",
                after_outcome="DETECTED",
                detection_improved=True,
            )

    def test_retest_fails_stays_unresolved(self):
        """Failed retest should go to UNRESOLVED, not MITIGATED."""
        result = CyberImmuneStateMachine.transition(
            "COMPARING",
            "UNRESOLVED",
            before_outcome="DETECTION_GAP",
            after_outcome="DETECTION_GAP",
            detection_improved=False,
        )
        assert result == "UNRESOLVED"

    def test_only_valid_mitigated_transition(self):
        """Only valid MITIGATED transition should succeed."""
        result = CyberImmuneStateMachine.transition(
            "COMPARING",
            "MITIGATED",
            before_outcome="DETECTION_GAP",
            after_outcome="DETECTED",
            detection_improved=True,
        )
        assert result == "MITIGATED"

    def test_before_after_comparison_deterministic_improvement(self):
        """BeforeAfterComparison determines improvement solely from evaluation records."""
        org_id = uuid4()

        before = PurpleEvaluation(
            evaluation_id="before-1",
            experiment_id="exp-1",
            execution_id="exec-1",
            organization_id=org_id,
            technique_id="T1003.001",
            detection_status="NOT_DETECTED",
            matched_rule_ids=[],
            evidence_event_ids=[],
            expected_detection=True,
            gap_reason="No rule matched",
        )
        after = PurpleEvaluation(
            evaluation_id="after-1",
            experiment_id="exp-1",
            execution_id="exec-2",
            organization_id=org_id,
            technique_id="T1003.001",
            detection_status="DETECTED",
            matched_rule_ids=["sigma-001"],
            evidence_event_ids=["evt-1"],
            expected_detection=True,
        )
        comparison = BeforeAfterComparison.from_evaluations(before, after, org_id)
        assert comparison.improved is True

    def test_no_improvement_comparison(self):
        """Same status before and after means no improvement."""
        org_id = uuid4()

        before = PurpleEvaluation(
            evaluation_id="before-2",
            experiment_id="exp-2",
            execution_id="exec-3",
            organization_id=org_id,
            technique_id="T1003.001",
            detection_status="NOT_DETECTED",
            matched_rule_ids=[],
            evidence_event_ids=[],
            expected_detection=True,
            gap_reason="No rule",
        )
        after = PurpleEvaluation(
            evaluation_id="after-2",
            experiment_id="exp-2",
            execution_id="exec-4",
            organization_id=org_id,
            technique_id="T1003.001",
            detection_status="NOT_DETECTED",
            matched_rule_ids=[],
            evidence_event_ids=[],
            expected_detection=True,
            gap_reason="Still no rule",
        )
        comparison = BeforeAfterComparison.from_evaluations(before, after, org_id)
        assert comparison.improved is False

    def test_regression_worsening_not_improvement(self):
        """DETECTED -> NOT_DETECTED is NOT improvement."""
        org_id = uuid4()

        before = PurpleEvaluation(
            evaluation_id="before-3",
            experiment_id="exp-3",
            execution_id="exec-5",
            organization_id=org_id,
            technique_id="T1003.001",
            detection_status="DETECTED",
            matched_rule_ids=["sigma-001"],
            evidence_event_ids=["evt-1"],
            expected_detection=True,
        )
        after = PurpleEvaluation(
            evaluation_id="after-3",
            experiment_id="exp-3",
            execution_id="exec-6",
            organization_id=org_id,
            technique_id="T1003.001",
            detection_status="NOT_DETECTED",
            matched_rule_ids=[],
            evidence_event_ids=[],
            expected_detection=True,
            gap_reason="Regression",
        )
        comparison = BeforeAfterComparison.from_evaluations(before, after, org_id)
        assert comparison.improved is False
