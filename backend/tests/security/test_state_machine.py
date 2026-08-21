"""SentinelForge — Phase 5: Experiment State Machine Verification.

Proves that:
- RedAgentStateMachine follows the deterministic transition table
- Invalid transitions raise InvalidStateTransition
- ExerciseStateMachine lifecycle is enforced
- Invalid transitions raise SecurityRejection
- Every state occupies exactly one at a time
- History is recorded correctly
"""

import pytest
from uuid import uuid4
from datetime import datetime, timezone

from sentinelforge.agents.red.state import RedAgentState, RedAgentStateMachine, _TRANSITIONS
from sentinelforge.agents.red.exceptions import InvalidStateTransition
from sentinelforge.domain.state_machine import ExerciseStateMachine, VALID_TRANSITIONS
from sentinelforge.domain.exceptions import SecurityRejection
from sentinelforge.domain.experiment import RetestResult


# ---------------------------------------------------------------------------
# RedAgentStateMachine: valid transitions
# ---------------------------------------------------------------------------

class TestRedAgentValidTransitions:
    def test_initial_state_is_idle(self):
        sm = RedAgentStateMachine()
        assert sm.state == RedAgentState.IDLE

    def test_idle_to_objective_received(self):
        sm = RedAgentStateMachine()
        sm.transition(RedAgentState.OBJECTIVE_RECEIVED)
        assert sm.state == RedAgentState.OBJECTIVE_RECEIVED

    def test_full_happy_path(self):
        sm = RedAgentStateMachine()
        sm.transition(RedAgentState.OBJECTIVE_RECEIVED)
        sm.transition(RedAgentState.CONTEXT_LOADING)
        sm.transition(RedAgentState.ANALYZING)
        sm.transition(RedAgentState.HYPOTHESIS_GENERATED)
        sm.transition(RedAgentState.SCENARIO_GENERATED)
        sm.transition(RedAgentState.NOVELTY_CHECK)
        sm.transition(RedAgentState.SAFETY_SUBMITTED)
        sm.transition(RedAgentState.ALLOWED)
        sm.transition(RedAgentState.EXECUTING)
        sm.transition(RedAgentState.OBSERVING)
        sm.transition(RedAgentState.EVALUATING)
        sm.transition(RedAgentState.LEARNING)
        sm.transition(RedAgentState.CONTINUE)
        sm.transition(RedAgentState.ANALYZING)
        sm.transition(RedAgentState.FINISHED)
        assert sm.state == RedAgentState.FINISHED

    def test_denied_to_refine_path(self):
        sm = RedAgentStateMachine()
        sm.transition(RedAgentState.OBJECTIVE_RECEIVED)
        sm.transition(RedAgentState.CONTEXT_LOADING)
        sm.transition(RedAgentState.ANALYZING)
        sm.transition(RedAgentState.HYPOTHESIS_GENERATED)
        sm.transition(RedAgentState.SCENARIO_GENERATED)
        sm.transition(RedAgentState.NOVELTY_CHECK)
        sm.transition(RedAgentState.SAFETY_SUBMITTED)
        sm.transition(RedAgentState.DENIED)
        sm.transition(RedAgentState.REFINE)
        sm.transition(RedAgentState.ANALYZING)
        assert sm.state == RedAgentState.ANALYZING

    def test_escalated_to_wait_path(self):
        sm = RedAgentStateMachine()
        sm.transition(RedAgentState.OBJECTIVE_RECEIVED)
        sm.transition(RedAgentState.CONTEXT_LOADING)
        sm.transition(RedAgentState.ANALYZING)
        sm.transition(RedAgentState.HYPOTHESIS_GENERATED)
        sm.transition(RedAgentState.SCENARIO_GENERATED)
        sm.transition(RedAgentState.NOVELTY_CHECK)
        sm.transition(RedAgentState.SAFETY_SUBMITTED)
        sm.transition(RedAgentState.ESCALATED)
        sm.transition(RedAgentState.WAIT)
        sm.transition(RedAgentState.ANALYZING)
        assert sm.state == RedAgentState.ANALYZING

    def test_wait_to_finished_path(self):
        sm = RedAgentStateMachine()
        sm.transition(RedAgentState.OBJECTIVE_RECEIVED)
        sm.transition(RedAgentState.CONTEXT_LOADING)
        sm.transition(RedAgentState.ANALYZING)
        sm.transition(RedAgentState.HYPOTHESIS_GENERATED)
        sm.transition(RedAgentState.SCENARIO_GENERATED)
        sm.transition(RedAgentState.NOVELTY_CHECK)
        sm.transition(RedAgentState.SAFETY_SUBMITTED)
        sm.transition(RedAgentState.ESCALATED)
        sm.transition(RedAgentState.WAIT)
        sm.transition(RedAgentState.FINISHED)
        assert sm.state == RedAgentState.FINISHED


# ---------------------------------------------------------------------------
# RedAgentStateMachine: invalid transitions
# ---------------------------------------------------------------------------

class TestRedAgentInvalidTransitions:
    def test_idle_to_executing_blocked(self):
        sm = RedAgentStateMachine()
        with pytest.raises(InvalidStateTransition):
            sm.transition(RedAgentState.EXECUTING)

    def test_idle_to_finished_blocked(self):
        sm = RedAgentStateMachine()
        with pytest.raises(InvalidStateTransition):
            sm.transition(RedAgentState.FINISHED)

    def test_analyzing_to_executing_blocked(self):
        sm = RedAgentStateMachine()
        sm.transition(RedAgentState.OBJECTIVE_RECEIVED)
        sm.transition(RedAgentState.CONTEXT_LOADING)
        sm.transition(RedAgentState.ANALYZING)
        with pytest.raises(InvalidStateTransition):
            sm.transition(RedAgentState.EXECUTING)

    def test_safety_submitted_to_executing_blocked(self):
        sm = RedAgentStateMachine()
        sm.transition(RedAgentState.OBJECTIVE_RECEIVED)
        sm.transition(RedAgentState.CONTEXT_LOADING)
        sm.transition(RedAgentState.ANALYZING)
        sm.transition(RedAgentState.HYPOTHESIS_GENERATED)
        sm.transition(RedAgentState.SCENARIO_GENERATED)
        sm.transition(RedAgentState.NOVELTY_CHECK)
        sm.transition(RedAgentState.SAFETY_SUBMITTED)
        with pytest.raises(InvalidStateTransition):
            sm.transition(RedAgentState.EXECUTING)

    def test_finished_is_terminal(self):
        sm = RedAgentStateMachine()
        sm.transition(RedAgentState.OBJECTIVE_RECEIVED)
        sm.transition(RedAgentState.CONTEXT_LOADING)
        sm.transition(RedAgentState.ANALYZING)
        sm.transition(RedAgentState.FINISHED)
        with pytest.raises(InvalidStateTransition):
            sm.transition(RedAgentState.ANALYZING)

    def test_executing_to_safety_blocked(self):
        sm = RedAgentStateMachine()
        sm.transition(RedAgentState.OBJECTIVE_RECEIVED)
        sm.transition(RedAgentState.CONTEXT_LOADING)
        sm.transition(RedAgentState.ANALYZING)
        sm.transition(RedAgentState.HYPOTHESIS_GENERATED)
        sm.transition(RedAgentState.SCENARIO_GENERATED)
        sm.transition(RedAgentState.NOVELTY_CHECK)
        sm.transition(RedAgentState.SAFETY_SUBMITTED)
        sm.transition(RedAgentState.ALLOWED)
        sm.transition(RedAgentState.EXECUTING)
        with pytest.raises(InvalidStateTransition):
            sm.transition(RedAgentState.SAFETY_SUBMITTED)


# ---------------------------------------------------------------------------
# RedAgentStateMachine: history and reset
# ---------------------------------------------------------------------------

class TestRedAgentHistoryAndReset:
    def test_history_records_all_transitions(self):
        sm = RedAgentStateMachine()
        sm.transition(RedAgentState.OBJECTIVE_RECEIVED)
        sm.transition(RedAgentState.CONTEXT_LOADING)
        sm.transition(RedAgentState.ANALYZING)
        assert len(sm.history) == 4
        assert sm.history[0] == RedAgentState.IDLE
        assert sm.history[-1] == RedAgentState.ANALYZING

    def test_can_transition_returns_bool(self):
        sm = RedAgentStateMachine()
        assert sm.can_transition(RedAgentState.OBJECTIVE_RECEIVED) is True
        assert sm.can_transition(RedAgentState.EXECUTING) is False

    def test_allowed_transitions_returns_frozenset(self):
        sm = RedAgentStateMachine()
        allowed = sm.allowed_transitions()
        assert RedAgentState.OBJECTIVE_RECEIVED in allowed
        assert RedAgentState.EXECUTING not in allowed

    def test_reset_returns_to_idle(self):
        sm = RedAgentStateMachine()
        sm.transition(RedAgentState.OBJECTIVE_RECEIVED)
        sm.transition(RedAgentState.CONTEXT_LOADING)
        sm.transition(RedAgentState.ANALYZING)
        sm.reset()
        assert sm.state == RedAgentState.IDLE
        assert sm.history == [RedAgentState.IDLE]


# ---------------------------------------------------------------------------
# RedAgentStateMachine: transition table completeness
# ---------------------------------------------------------------------------

class TestRedAgentTransitionTableCompleteness:
    def test_all_states_have_transitions(self):
        for state in RedAgentState:
            assert state in _TRANSITIONS, f"State {state.value} missing from transition table"

    def test_finished_has_no_transitions(self):
        assert _TRANSITIONS[RedAgentState.FINISHED] == set()

    def test_executing_only_goes_to_observing(self):
        assert _TRANSITIONS[RedAgentState.EXECUTING] == {RedAgentState.OBSERVING}


# ---------------------------------------------------------------------------
# ExerciseStateMachine: valid transitions
# ---------------------------------------------------------------------------

class TestExerciseValidTransitions:
    def test_created_to_planning(self):
        result = ExerciseStateMachine.transition("CREATED", "PLANNING")
        assert result == "PLANNING"

    def test_created_to_scenario_proposed(self):
        result = ExerciseStateMachine.transition("CREATED", "SCENARIO_PROPOSED")
        assert result == "SCENARIO_PROPOSED"

    def test_planning_to_policy_check(self):
        result = ExerciseStateMachine.transition("PLANNING", "POLICY_CHECK")
        assert result == "POLICY_CHECK"

    def test_policy_check_to_approved(self):
        result = ExerciseStateMachine.transition("POLICY_CHECK", "APPROVED")
        assert result == "APPROVED"

    def test_approved_to_simulating(self):
        result = ExerciseStateMachine.transition("APPROVED", "SIMULATING")
        assert result == "SIMULATING"

    def test_full_detection_lifecycle(self):
        result = ExerciseStateMachine.transition("CREATED", "PLANNING")
        result = ExerciseStateMachine.transition(result, "POLICY_CHECK")
        result = ExerciseStateMachine.transition(result, "APPROVED")
        result = ExerciseStateMachine.transition(result, "SIMULATING")
        result = ExerciseStateMachine.transition(result, "COLLECTING")
        result = ExerciseStateMachine.transition(result, "DETECTING")
        result = ExerciseStateMachine.transition(result, "DETECTED")
        result = ExerciseStateMachine.transition(result, "COMPLETED")
        assert result == "COMPLETED"

    def test_detection_gap_to_remediating(self):
        result = ExerciseStateMachine.transition("DETECTION_GAP", "REMEDIATING")
        assert result == "REMEDIATING"

    def test_detection_gap_to_analyzing(self):
        result = ExerciseStateMachine.transition("DETECTION_GAP", "ANALYZING")
        assert result == "ANALYZING"

    def test_remediating_to_retesting_blocked(self):
        with pytest.raises(SecurityRejection):
            ExerciseStateMachine.transition("REMEDIATING", "RETESTING")

    def test_retesting_to_verified(self):
        retest = RetestResult(
            scenario_id=uuid4(),
            before_outcome="DETECTION_GAP",
            after_outcome="DETECTED",
            detection_improved=True,
            validated_rule_ids=["rule1"],
        )
        result = ExerciseStateMachine.transition("RETESTING", "VERIFIED", retest_result=retest)
        assert result == "VERIFIED"

    def test_retesting_to_completed(self):
        result = ExerciseStateMachine.transition("RETESTING", "COMPLETED")
        assert result == "COMPLETED"


# ---------------------------------------------------------------------------
# ExerciseStateMachine: invalid transitions
# ---------------------------------------------------------------------------

class TestExerciseInvalidTransitions:
    def test_created_to_approved_blocked(self):
        with pytest.raises(SecurityRejection) as exc_info:
            ExerciseStateMachine.transition("CREATED", "APPROVED")
        assert "INVALID_STATE_TRANSITION" in str(exc_info.value.code)

    def test_simulating_to_approved_blocked(self):
        with pytest.raises(SecurityRejection):
            ExerciseStateMachine.transition("SIMULATING", "APPROVED")

    def test_completed_is_terminal(self):
        with pytest.raises(SecurityRejection):
            ExerciseStateMachine.transition("COMPLETED", "SIMULATING")

    def test_retesting_to_simulating_blocked(self):
        with pytest.raises(SecurityRejection):
            ExerciseStateMachine.transition("RETESTING", "SIMULATING")


# ---------------------------------------------------------------------------
# ExerciseStateMachine: VERIFIED transition guards
# ---------------------------------------------------------------------------

class TestExerciseVerifiedGuards:
    def test_verified_requires_retest_result_object(self):
        with pytest.raises(SecurityRejection) as exc_info:
            ExerciseStateMachine.transition("RETESTING", "VERIFIED", has_retest_result=True)
        assert "RetestResult object" in str(exc_info.value.message)

    def test_verified_requires_before_detection_gap(self):
        retest = RetestResult(
            scenario_id=uuid4(),
            before_outcome="DETECTED",
            after_outcome="DETECTED",
            detection_improved=True,
        )
        with pytest.raises(SecurityRejection) as exc_info:
            ExerciseStateMachine.transition("RETESTING", "VERIFIED", retest_result=retest)
        assert "before_outcome must be a detection failure" in str(exc_info.value.message)

    def test_verified_requires_after_detected(self):
        retest = RetestResult(
            scenario_id=uuid4(),
            before_outcome="DETECTION_GAP",
            after_outcome="NOT_DETECTED",
            detection_improved=True,
        )
        with pytest.raises(SecurityRejection) as exc_info:
            ExerciseStateMachine.transition("RETESTING", "VERIFIED", retest_result=retest)
        assert "after_outcome must be DETECTED" in str(exc_info.value.message)

    def test_verified_requires_detection_improved_true(self):
        retest = RetestResult(
            scenario_id=uuid4(),
            before_outcome="DETECTION_GAP",
            after_outcome="DETECTED",
            detection_improved=False,
        )
        with pytest.raises(SecurityRejection) as exc_info:
            ExerciseStateMachine.transition("RETESTING", "VERIFIED", retest_result=retest)
        assert "detection_improved must be True" in str(exc_info.value.message)

    def test_verified_passes_with_valid_retest(self):
        retest = RetestResult(
            scenario_id=uuid4(),
            before_outcome="NOT_DETECTED",
            after_outcome="DETECTED",
            detection_improved=True,
            validated_rule_ids=["rule1"],
        )
        result = ExerciseStateMachine.transition("RETESTING", "VERIFIED", retest_result=retest)
        assert result == "VERIFIED"


# ---------------------------------------------------------------------------
# ExerciseStateMachine: transition table completeness
# ---------------------------------------------------------------------------

class TestExerciseTransitionTableCompleteness:
    def test_all_states_in_table(self):
        expected_states = {
            "CREATED", "SCENARIO_PROPOSED", "PLANNING", "POLICY_CHECK",
            "APPROVED", "SIMULATING", "COLLECTING", "DETECTING",
            "DETECTED", "DETECTION_GAP", "ANALYZING", "AWAITING_APPROVAL",
            "REMEDIATING", "RETESTING",
            "VULNERABILITY_FOUND", "VULNERABILITY_ANALYZING",
            "REMEDIATION_PROPOSED", "REMEDIATION_VALIDATING",
            "CLONE_CREATING", "ROLLING_BACK", "REMEDIATION_FAILED",
            "REQUIRES_HUMAN_REVIEW",
        }
        assert set(VALID_TRANSITIONS.keys()) == expected_states

    def test_requires_human_review_is_terminal(self):
        assert VALID_TRANSITIONS["REQUIRES_HUMAN_REVIEW"] == []
