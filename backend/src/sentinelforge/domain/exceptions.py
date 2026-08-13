from enum import Enum

class SecurityRejectionCode(str, Enum):
    POLICY_DENIED = "POLICY_DENIED"
    INVALID_ACTION_IR = "INVALID_ACTION_IR"
    INVALID_TARGET = "INVALID_TARGET"
    INVALID_EXECUTABLE = "INVALID_EXECUTABLE"
    INVALID_ARGUMENTS = "INVALID_ARGUMENTS"
    UNAUTHORIZED_USER = "UNAUTHORIZED_USER"
    EXPIRED_BLUEPRINT = "EXPIRED_BLUEPRINT"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    TAMPERED_BLUEPRINT = "TAMPERED_BLUEPRINT"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"

class SecurityRejection(Exception):
    def __init__(self, code: SecurityRejectionCode, message: str, entity_id: str = None):
        self.code = code
        self.message = message
        self.entity_id = entity_id
        super().__init__(f"[{code.value}] {message}")
