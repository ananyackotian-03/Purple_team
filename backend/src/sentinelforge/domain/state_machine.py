from .exceptions import SecurityRejection, SecurityRejectionCode

VALID_TRANSITIONS = {
    "CREATED": ["PLANNING"],
    "PLANNING": ["POLICY_CHECK"],
    "POLICY_CHECK": ["APPROVED"],
    "APPROVED": ["SIMULATING"],
    "SIMULATING": ["COLLECTING"],
    "COLLECTING": ["DETECTING"],
    "DETECTING": ["ANALYZING"],
    "ANALYZING": ["AWAITING_APPROVAL"],
    "AWAITING_APPROVAL": ["RETESTING"],
    "RETESTING": ["COMPLETED", "VERIFIED"],
}

class ExerciseStateMachine:
    @staticmethod
    def transition(current_state: str, new_state: str, has_retest_result: bool = False):
        if new_state not in VALID_TRANSITIONS.get(current_state, []):
            raise SecurityRejection(SecurityRejectionCode.INVALID_STATE_TRANSITION, f"Cannot transition from {current_state} to {new_state}")
            
        if new_state == "VERIFIED" and not has_retest_result:
            raise SecurityRejection(SecurityRejectionCode.VERIFICATION_FAILED, "VERIFIED state requires a valid RetestResult")
            
        return new_state
