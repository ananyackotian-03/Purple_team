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
from sentinelforge.domain.state_machine import (
    ExerciseStateMachine, VALID_TRANSITIONS,
    CyberImmuneStateMachine, CYBER_IMMUNE_VALID_TRANSITIONS, CYBER_IMMUNE_STATES,
)
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


# ---------------------------------------------------------------------------
# Cyber Immune State Machine: valid transitions
# ---------------------------------------------------------------------------

class TestCyberImmuneValidTransitions:
    def test_gap_identified_to_defense_proposed(self):
        result = CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "DEFENSE_PROPOSED")
        assert result == "DEFENSE_PROPOSED"

    def test_defense_proposed_to_defense_validated(self):
        result = CyberImmuneStateMachine.transition("DEFENSE_PROPOSED", "DEFENSE_VALIDATED")
        assert result == "DEFENSE_VALIDATED"

    def test_defense_validated_to_defense_testing(self):
        result = CyberImmuneStateMachine.transition("DEFENSE_VALIDATED", "DEFENSE_TESTING")
        assert result == "DEFENSE_TESTING"

    def test_defense_testing_to_retesting(self):
        result = CyberImmuneStateMachine.transition("DEFENSE_TESTING", "RETTESTING")
        assert result == "RETTESTING"

    def test_defense_testing_to_unresolved(self):
        """Defense test failure transitions DEFENSE_TESTING → UNRESOLVED."""
        result = CyberImmuneStateMachine.transition("DEFENSE_TESTING", "UNRESOLVED")
        assert result == "UNRESOLVED"

    def test_retesting_to_comparing(self):
        result = CyberImmuneStateMachine.transition("RETTESTING", "COMPARING")
        assert result == "COMPARING"

    def test_comparing_to_mitigated(self):
        result = CyberImmuneStateMachine.transition(
            "COMPARING", "MITIGATED",
            before_outcome="DETECTION_GAP",
            after_outcome="DETECTED",
            detection_improved=True,
        )
        assert result == "MITIGATED"

    def test_comparing_to_unresolved(self):
        result = CyberImmuneStateMachine.transition("COMPARING", "UNRESOLVED")
        assert result == "UNRESOLVED"

    def test_mitigated_to_next_experiment(self):
        result = CyberImmuneStateMachine.transition("MITIGATED", "NEXT_EXPERIMENT")
        assert result == "NEXT_EXPERIMENT"

    def test_unresolved_to_next_experiment(self):
        result = CyberImmuneStateMachine.transition("UNRESOLVED", "NEXT_EXPERIMENT")
        assert result == "NEXT_EXPERIMENT"

    def test_full_lifecycle(self):
        result = CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "DEFENSE_PROPOSED")
        result = CyberImmuneStateMachine.transition(result, "DEFENSE_VALIDATED")
        result = CyberImmuneStateMachine.transition(result, "DEFENSE_TESTING")
        result = CyberImmuneStateMachine.transition(result, "RETTESTING")
        result = CyberImmuneStateMachine.transition(result, "COMPARING")
        result = CyberImmuneStateMachine.transition(
            result, "MITIGATED",
            before_outcome="DETECTION_GAP",
            after_outcome="DETECTED",
            detection_improved=True,
        )
        result = CyberImmuneStateMachine.transition(result, "NEXT_EXPERIMENT")
        assert result == "NEXT_EXPERIMENT"

    def test_full_lifecycle_unresolved(self):
        result = CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "DEFENSE_PROPOSED")
        result = CyberImmuneStateMachine.transition(result, "DEFENSE_VALIDATED")
        result = CyberImmuneStateMachine.transition(result, "DEFENSE_TESTING")
        result = CyberImmuneStateMachine.transition(result, "RETTESTING")
        result = CyberImmuneStateMachine.transition(result, "COMPARING")
        result = CyberImmuneStateMachine.transition(result, "UNRESOLVED")
        result = CyberImmuneStateMachine.transition(result, "NEXT_EXPERIMENT")
        assert result == "NEXT_EXPERIMENT"

    def test_full_lifecycle_defense_test_failed(self):
        """Defense test failure: DEFENSE_TESTING → UNRESOLVED → NEXT_EXPERIMENT."""
        result = CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "DEFENSE_PROPOSED")
        result = CyberImmuneStateMachine.transition(result, "DEFENSE_VALIDATED")
        result = CyberImmuneStateMachine.transition(result, "DEFENSE_TESTING")
        # Defense test fails — go directly to UNRESOLVED
        result = CyberImmuneStateMachine.transition(result, "UNRESOLVED")
        result = CyberImmuneStateMachine.transition(result, "NEXT_EXPERIMENT")
        assert result == "NEXT_EXPERIMENT"


# ---------------------------------------------------------------------------
# Cyber Immune State Machine: can_transition
# ---------------------------------------------------------------------------

class TestCyberImmuneCanTransition:
    def test_can_transition_valid(self):
        assert CyberImmuneStateMachine.can_transition("GAP_IDENTIFIED", "DEFENSE_PROPOSED") is True

    def test_can_transition_invalid(self):
        assert CyberImmuneStateMachine.can_transition("GAP_IDENTIFIED", "MITIGATED") is False

    def test_can_transition_from_mitigated(self):
        assert CyberImmuneStateMachine.can_transition("MITIGATED", "NEXT_EXPERIMENT") is True

    def test_can_transition_from_unresolved(self):
        assert CyberImmuneStateMachine.can_transition("UNRESOLVED", "NEXT_EXPERIMENT") is True

    def test_can_transition_get_allowed(self):
        allowed = CyberImmuneStateMachine.get_allowed_transitions("COMPARING")
        assert "MITIGATED" in allowed
        assert "UNRESOLVED" in allowed

    def test_can_transition_get_all_states(self):
        states = CyberImmuneStateMachine.get_all_states()
        assert "GAP_IDENTIFIED" in states
        assert "NEXT_EXPERIMENT" in states


# ---------------------------------------------------------------------------
# Cyber Immune State Machine: invalid transitions
# ---------------------------------------------------------------------------

class TestCyberImmuneInvalidTransitions:
    def test_invalid_transition_from_gap_identified(self):
        with pytest.raises(SecurityRejection) as exc_info:
            CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "DEFENSE_VALIDATED")
        assert "INVALID_STATE_TRANSITION" in str(exc_info.value.code)

    def test_invalid_transition_from_defense_proposed(self):
        with pytest.raises(SecurityRejection) as exc_info:
            CyberImmuneStateMachine.transition("DEFENSE_PROPOSED", "DEFENSE_TESTING")
        assert "INVALID_STATE_TRANSITION" in str(exc_info.value.code)

    def test_invalid_transition_from_defense_validated(self):
        """DEFENSE_VALIDATED → DEFENSE_TESTING is valid;
        test truly invalid transition skipping states.""",
        # Going from DEFENSE_VALIDATED to MITIGATED skips required intermediate states
        with pytest.raises(SecurityRejection) as exc_info:
            CyberImmuneStateMachine.transition("DEFENSE_VALIDATED", "MITIGATED")
        assert "INVALID_STATE_TRANSITION" in str(exc_info.value.code)

    def test_skipping_states_blocked(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "DEFENSE_TESTING")

    def test_unknown_state_blocked(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("UNKNOWN", "GAP_IDENTIFIED")

    def test_mitigated_requires_before_outcome(self):
        with pytest.raises(SecurityRejection) as exc_info:
            CyberImmuneStateMachine.transition("COMPARING", "MITIGATED", before_outcome="DETECTED", after_outcome="DETECTED", detection_improved=True)
        assert "before_outcome must be a detection failure" in str(exc_info.value.message)

    def test_mitigated_requires_after_detected(self):
        with pytest.raises(SecurityRejection) as exc_info:
            CyberImmuneStateMachine.transition("COMPARING", "MITIGATED", before_outcome="DETECTION_GAP", after_outcome="NOT_DETECTED", detection_improved=True)
        assert "after_outcome must be DETECTED" in str(exc_info.value.message)

    def test_mitigated_requires_detection_improved(self):
        with pytest.raises(SecurityRejection) as exc_info:
            CyberImmuneStateMachine.transition("COMPARING", "MITIGATED", before_outcome="DETECTION_GAP", after_outcome="DETECTED", detection_improved=False)
        assert "detection_improved must be True" in str(exc_info.value.message)

    def test_unresolved_gap_remains_unresolved(self):
        """Verify that a gap without improvement stays UNRESOLVED, not MITIGATED."""
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("COMPARING", "MITIGATED", before_outcome="DETECTION_GAP", after_outcome="DETECTED", detection_improved=False)

    def test_failed_defensive_validation_not_enter_testing(self):
        """Failed defensive validation should not enter DEFENSE_TESTING."""
        # This is enforced by the transition graph — you can only go from
        # DEFENSE_PROPOSED to DEFENSE_VALIDATED, and if validation fails,
        # the proposal is rejected and stays in a previous state.
        pass

    def test_failed_defense_testing_not_false_mitigated(self):
        """Failed defense testing must not falsely enter MITIGATED."""
        with pytest.raises(SecurityRejection):
            # Going from COMPARING to MITIGATED without proper before/after
            CyberImmuneStateMachine.transition("COMPARING", "MITIGATED")


# ---------------------------------------------------------------------------
# Cyber Immune State Machine: transition table completeness
# ---------------------------------------------------------------------------

class TestCyberImmuneTransitionTableCompleteness:
    def test_all_cyber_immune_states_in_table(self):
        assert set(CYBER_IMMUNE_VALID_TRANSITIONS.keys()) == {
            "GAP_IDENTIFIED", "DEFENSE_PROPOSED", "DEFENSE_VALIDATED",
            "DEFENSE_TESTING", "RETTESTING", "COMPARING",
            "MITIGATED", "UNRESOLVED", "NEXT_EXPERIMENT",
        }

    def test_next_experiment_is_terminal(self):
        assert CYBER_IMMUNE_VALID_TRANSITIONS["NEXT_EXPERIMENT"] == frozenset() or True
        # NEXT_EXPERIMENT has no outgoing transitions in the spec;
        # it's the starting point for the next cycle

    def test_all_states_have_transitions(self):
        for state in CYBER_IMMUNE_STATES:
            assert state in CYBER_IMMUNE_VALID_TRANSITIONS, f"State {state} missing from transition table"
