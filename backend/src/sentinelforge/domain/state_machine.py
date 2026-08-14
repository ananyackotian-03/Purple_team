from typing import Optional, Any
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
}


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

