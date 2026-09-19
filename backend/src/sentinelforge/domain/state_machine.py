from typing import Optional, Any, Dict, Set, FrozenSet
from sentinelforge.domain.exceptions import SecurityRejection, SecurityRejectionCode
from sentinelforge.domain.experiment import RetestResult

VALID_TRANSITIONS = {
    "CREATED": ["PLANNING", "SCENARIO_PROPOSED"],
    "SCENARIO_PROPOSED": ["POLICY_CHECK", "REJECTED"],
    "PLANNING": ["POLICY_CHECK"],
    "POLICY_CHECK": ["APPROVED", "REJECTED"],
    "APPROVED": ["SIMULATING"],
    "SIMULATING": ["COLLECTING"],
    "COLLECTING": ["DETECTING"],
    "DETECTING": ["ANALYZING", "DETECTED", "DETECTION_GAP"],
    "DETECTED": ["COMPLETED"],
    "DETECTION_GAP": ["ANALYZING", "REMEDIATING"],
    "ANALYZING": ["AWAITING_APPROVAL", "REMEDIATING"],
    "AWAITING_APPROVAL": ["RETESTING"],
    "REMEDIATING": ["RETESTING"],
    "RETESTING": ["COMPLETED", "VERIFIED"],
    # Branch 2: Application Remediation states
    "VULNERABILITY_FOUND": ["VULNERABILITY_ANALYZING"],
    "VULNERABILITY_ANALYZING": ["REMEDIATION_PROPOSED", "REMEDIATION_FAILED"],
    "REMEDIATION_PROPOSED": ["REMEDIATION_VALIDATING"],
    "REMEDIATION_VALIDATING": ["CLONE_CREATING", "REMEDIATION_FAILED"],
    "CLONE_CREATING": ["REMEDIATING", "ROLLING_BACK", "REMEDIATION_FAILED"],
    "ROLLING_BACK": ["REMEDIATION_FAILED", "CLONE_CREATING"],
    "REMEDIATION_FAILED": ["REMEDIATION_PROPOSED"],
    "REMEDIATING": ["REQUIRES_HUMAN_REVIEW", "REMEDIATION_FAILED"],
    "REQUIRES_HUMAN_REVIEW": [],
}


# ---------------------------------------------------------------------------
# Cyber Immune State Machine
# ---------------------------------------------------------------------------

CYBER_IMMUNE_VALID_TRANSITIONS: Dict[str, FrozenSet[str]] = {
    "GAP_IDENTIFIED": frozenset({"DEFENSE_PROPOSED"}),
    "DEFENSE_PROPOSED": frozenset({"DEFENSE_VALIDATED"}),
    "DEFENSE_VALIDATED": frozenset({"DEFENSE_TESTING"}),
    "DEFENSE_TESTING": frozenset({"RETTESTING", "UNRESOLVED"}),
    "RETTESTING": frozenset({"COMPARING"}),
    "COMPARING": frozenset({"MITIGATED", "UNRESOLVED"}),
    "MITIGATED": frozenset({"NEXT_EXPERIMENT"}),
    "UNRESOLVED": frozenset({"NEXT_EXPERIMENT"}),
    "NEXT_EXPERIMENT": frozenset(),
}

CYBER_IMMUNE_STATES = frozenset(
    [
        "GAP_IDENTIFIED",
        "DEFENSE_PROPOSED",
        "DEFENSE_VALIDATED",
        "DEFENSE_TESTING",
        "RETTESTING",
        "COMPARING",
        "MITIGATED",
        "UNRESOLVED",
        "NEXT_EXPERIMENT",
    ]
)


class CyberImmuneStateMachine:
    """Deterministic state machine for the Cyber Immune lifecycle.

    Lifecycle: GAP_IDENTIFIED → DEFENSE_PROPOSED → DEFENSE_VALIDATED →
    DEFENSE_TESTING → RETTESTING → COMPARING → (MITIGATED | UNRESOLVED) →
    NEXT_EXPERIMENT

    Guarantees:
    - Invalid transitions are rejected deterministically via SecurityRejection
    - Only actual before/after detection improvement can produce MITIGATED
    - Failed defensive validation never enters DEFENSE_TESTING
    - Failed defense testing never falsely enters MITIGATED
    - Unresolved gaps remain UNRESOLVED unless actual improvement is shown
    - Both MITIGATED and UNRESOLVED can proceed to NEXT_EXPERIMENT
    """

    @staticmethod
    def transition(
        current_state: str,
        new_state: str,
        before_outcome: str = "",
        after_outcome: str = "",
        detection_improved: bool = False,
    ) -> str:
        """Transition the Cyber Immune state machine.

        Args:
            current_state: The current state
            new_state: The target state
            before_outcome: Outcome before the defense was applied
                            (e.g. "DETECTION_GAP" or "NOT_DETECTED")
            after_outcome: Outcome after the defense was applied
                           (e.g. "DETECTED" or "DETECTION_GAP")
            detection_improved: Whether detection actually improved

        Returns:
            The new state name

        Raises:
            SecurityRejection: If the transition is invalid
        }
        """
        # Gate 1: Validate that new_state is a valid Cyber Immune state
        if new_state not in CYBER_IMMUNE_STATES:
            raise SecurityRejection(
                SecurityRejectionCode.INVALID_STATE_TRANSITION,
                f"Invalid Cyber Immune state: {new_state}",
            )

        # Gate 2: Validate transition is allowed from current_state
        allowed = CYBER_IMMUNE_VALID_TRANSITIONS.get(current_state)
        if allowed is None:
            raise SecurityRejection(
                SecurityRejectionCode.INVALID_STATE_TRANSITION,
                f"No transition definition for current state: {current_state}",
            )

        if new_state not in allowed:
            raise SecurityRejection(
                SecurityRejectionCode.INVALID_STATE_TRANSITION,
                f"Cannot transition from {current_state} to {new_state}",
            )

        # Gate 3: Validate state-specific guards

        # COMPARING → MITIGATED requires actual before/after detection improvement
        if current_state == "COMPARING" and new_state == "MITIGATED":
            if before_outcome not in ("DETECTION_GAP", "NOT_DETECTED"):
                raise SecurityRejection(
                    SecurityRejectionCode.VERIFICATION_FAILED,
                    f"MITIGATED transition rejected: before_outcome must be a "
                    f"detection failure (got {before_outcome})",
                )

            if after_outcome != "DETECTED":
                raise SecurityRejection(
                    SecurityRejectionCode.VERIFICATION_FAILED,
                    f"MITIGATED transition rejected: after_outcome must be "
                    f"DETECTED (got {after_outcome})",
                )

            if detection_improved is not True:
                raise SecurityRejection(
                    SecurityRejectionCode.VERIFICATION_FAILED,
                    "MITIGATED transition rejected: detection_improved must be True "
                    "for actual successful before/after comparison",
                )

        # COMPARING → UNRESOLVED: always allowed from COMPARING (no guards needed;
        # the LLM/declarative path chooses this when improvement isn't shown)

        # MITIGATED → NEXT_EXPERIMENT and UNRESOLVED → NEXT_EXPERIMENT
        # have no additional guards — they are terminal progression states

        return new_state

    @staticmethod
    def can_transition(current_state: str, new_state: str) -> bool:
        """Check if a transition is valid without executing it.

        Returns True if the transition is allowed, False otherwise.
        """
        allowed = CYBER_IMMUNE_VALID_TRANSITIONS.get(current_state)
        if allowed is None:
            return False
        return new_state in allowed

    @staticmethod
    def get_allowed_transitions(current_state: str) -> Set[str]:
        """Get all valid next states from the current state."""
        allowed = CYBER_IMMUNE_VALID_TRANSITIONS.get(current_state, set())
        return set(allowed)

    @staticmethod
    def get_all_states() -> FrozenSet[str]:
        """Get all valid Cyber Immune states."""
        return CYBER_IMMUNE_STATES


class ExerciseStateMachine:
    @staticmethod
    def transition(
        current_state: str,
        new_state: str,
        has_retest_result: bool = False,
        retest_result: Optional[Any] = None,
    ) -> str:
        if new_state not in VALID_TRANSITIONS.get(current_state, []):
            raise SecurityRejection(
                SecurityRejectionCode.INVALID_STATE_TRANSITION,
                f"Cannot transition from {current_state} to {new_state}",
            )

        if new_state == "VERIFIED":
            res = retest_result if retest_result is not None else (has_retest_result if not isinstance(has_retest_result, bool) else None)

            if res is None or isinstance(res, bool):
                raise SecurityRejection(
                    SecurityRejectionCode.VERIFICATION_FAILED,
                    "VERIFIED state requires a valid RetestResult object, bare boolean is strictly rejected",
                )

            before_out = str(getattr(res, "before_outcome", "") or "")
            after_out = str(getattr(res, "after_outcome", "") or "")
            det_imp = getattr(res, "detection_improved", False)

            if before_out not in ("DETECTION_GAP", "NOT_DETECTED"):
                raise SecurityRejection(
                    SecurityRejectionCode.VERIFICATION_FAILED,
                    f"VERIFIED transition rejected: before_outcome must be a detection failure (got {before_out})",
                )

            if after_out != "DETECTED":
                raise SecurityRejection(
                    SecurityRejectionCode.VERIFICATION_FAILED,
                    f"VERIFIED transition rejected: after_outcome must be DETECTED (got {after_out})",
                )

            if det_imp is not True and str(det_imp).lower() != "true":
                raise SecurityRejection(
                    SecurityRejectionCode.VERIFICATION_FAILED,
                    "VERIFIED transition rejected: detection_improved must be True",
                )

        return new_state

