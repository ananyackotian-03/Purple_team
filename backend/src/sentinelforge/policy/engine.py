from datetime import datetime, timezone, timedelta
from ..domain.action_ir import ActionIR
from ..domain.exceptions import SecurityRejection, SecurityRejectionCode
from .allowlists import ALLOWED_EXECUTABLES, ALLOWED_BASH_COMMANDS

CLOCK_SKEW_TOLERANCE = timedelta(seconds=5)

class PolicyEngine:
    @staticmethod
    def validate(ir: ActionIR, current_time: datetime = None):
        if current_time is None:
            current_time = datetime.now(timezone.utc)
            
        if ir.issued_at >= ir.expires_at:
            raise SecurityRejection(SecurityRejectionCode.INVALID_ACTION_IR, "issued_at must be before expires_at")
        if ir.issued_at > current_time + CLOCK_SKEW_TOLERANCE:
            raise SecurityRejection(SecurityRejectionCode.INVALID_ACTION_IR, "Blueprint issued in the future")
        if current_time > ir.expires_at:
            raise SecurityRejection(SecurityRejectionCode.EXPIRED_BLUEPRINT, "Blueprint is expired")
            
        if ir.target != "sentinelforge-target":
            raise SecurityRejection(SecurityRejectionCode.INVALID_TARGET, "Unauthorized target")
        if ir.run_as_user != "labuser":
            raise SecurityRejection(SecurityRejectionCode.UNAUTHORIZED_USER, "Unauthorized user")
            
        if ir.executable not in ALLOWED_EXECUTABLES:
            raise SecurityRejection(SecurityRejectionCode.INVALID_EXECUTABLE, "Unauthorized executable")
            
        if ir.executable in {"/usr/bin/bash", "/usr/bin/sh"}:
            if len(ir.arguments) != 2 or ir.arguments[0] != "-c":
                raise SecurityRejection(SecurityRejectionCode.INVALID_ARGUMENTS, "bash requires exact -c argument")
            if ir.arguments[1] not in ALLOWED_BASH_COMMANDS:
                raise SecurityRejection(SecurityRejectionCode.POLICY_DENIED, "Command not in exact match allowlist")
                
        if ir.executable == "/usr/bin/cat" and ".." in ir.arguments[0]:
            raise SecurityRejection(SecurityRejectionCode.POLICY_DENIED, "Path traversal denied")
            
        return True
