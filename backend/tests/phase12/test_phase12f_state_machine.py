"""Phase 12F — State Machine Attacks.

Attempt invalid Cyber Immune state machine transitions.
"""

import pytest
from uuid import uuid4

from sentinelforge.domain.state_machine import CyberImmuneStateMachine
from sentinelforge.domain.exceptions import SecurityRejection


class TestInvalidDirectTransitions:
    def test_gap_identified_to_mitigated(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "MITIGATED")

    def test_gap_identified_to_next_experiment(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "NEXT_EXPERIMENT")

    def test_defense_proposed_to_retesting(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("DEFENSE_PROPOSED", "RETTESTING")

    def test_defense_validated_to_retesting(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("DEFENSE_VALIDATED", "RETTESTING")

    def test_defense_testing_to_mitigated(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "DEFENSE_TESTING", "MITIGATED",
                before_outcome="DETECTION_GAP", after_outcome="DETECTED",
                detection_improved=True,
            )

    def test_retesting_to_mitigated(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "RETTESTING", "MITIGATED",
                before_outcome="DETECTION_GAP", after_outcome="DETECTED",
                detection_improved=True,
            )

    def test_comparing_to_mitigated_without_improvement(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING", "MITIGATED",
                before_outcome="DETECTION_GAP",
                after_outcome="DETECTION_GAP",
                detection_improved=False,
            )

    def test_comparing_to_mitigated_with_forged_values(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING", "MITIGATED",
                before_outcome="DETECTED",
                after_outcome="DETECTED",
                detection_improved=True,
            )

    def test_mitigated_to_defense_proposed(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("MITIGATED", "DEFENSE_PROPOSED")

    def test_unresolved_to_defense_proposed(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("UNRESOLVED", "DEFENSE_PROPOSED")

    def test_next_experiment_to_anything(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("NEXT_EXPERIMENT", "GAP_IDENTIFIED")


class TestInvalidStateNames:
    def test_invalid_state_name(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "FAKE_STATE")

    def test_empty_state_name(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "")

    def test_unknown_state(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "RANDOM")


class TestMITIGATEDGuardsEnforced:
    def test_mitigated_requires_before_detection_gap(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING", "MITIGATED",
                before_outcome="DETECTED",
                after_outcome="DETECTED",
                detection_improved=True,
            )

    def test_mitigated_requires_before_not_detected(self):
        result = CyberImmuneStateMachine.transition(
            "COMPARING", "MITIGATED",
            before_outcome="NOT_DETECTED",
            after_outcome="DETECTED",
            detection_improved=True,
        )
        assert result == "MITIGATED"

    def test_mitigated_requires_after_detected(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING", "MITIGATED",
                before_outcome="NOT_DETECTED",
                after_outcome="NOT_DETECTED",
                detection_improved=True,
            )

    def test_mitigated_requires_detection_improved_true(self):
        with pytest.raises(SecurityRejection):
            CyberImmuneStateMachine.transition(
                "COMPARING", "MITIGATED",
                before_outcome="NOT_DETECTED",
                after_outcome="DETECTED",
                detection_improved=False,
            )


class TestValidTransitions:
    def test_gap_identified_to_defense_proposed(self):
        result = CyberImmuneStateMachine.transition("GAP_IDENTIFIED", "DEFENSE_PROPOSED")
        assert result == "DEFENSE_PROPOSED"

    def test_defense_proposed_to_validated(self):
        result = CyberImmuneStateMachine.transition("DEFENSE_PROPOSED", "DEFENSE_VALIDATED")
        assert result == "DEFENSE_VALIDATED"

    def test_defense_validated_to_testing(self):
        result = CyberImmuneStateMachine.transition("DEFENSE_VALIDATED", "DEFENSE_TESTING")
        assert result == "DEFENSE_TESTING"

    def test_defense_testing_to_retesting(self):
        result = CyberImmuneStateMachine.transition("DEFENSE_TESTING", "RETTESTING")
        assert result == "RETTESTING"

    def test_defense_testing_to_unresolved(self):
        result = CyberImmuneStateMachine.transition("DEFENSE_TESTING", "UNRESOLVED")
        assert result == "UNRESOLVED"

    def test_retesting_to_comparing(self):
        result = CyberImmuneStateMachine.transition("RETTESTING", "COMPARING")
        assert result == "COMPARING"

    def test_comparing_to_unresolved(self):
        result = CyberImmuneStateMachine.transition("COMPARING", "UNRESOLVED")
        assert result == "UNRESOLVED"

    def test_mitigated_to_next_experiment(self):
        result = CyberImmuneStateMachine.transition(
            "COMPARING", "MITIGATED",
            before_outcome="DETECTION_GAP",
            after_outcome="DETECTED",
            detection_improved=True,
        )
        assert result == "MITIGATED"
        result = CyberImmuneStateMachine.transition("MITIGATED", "NEXT_EXPERIMENT")
        assert result == "NEXT_EXPERIMENT"

    def test_unresolved_to_next_experiment(self):
        result = CyberImmuneStateMachine.transition("UNRESOLVED", "NEXT_EXPERIMENT")
        assert result == "NEXT_EXPERIMENT"
