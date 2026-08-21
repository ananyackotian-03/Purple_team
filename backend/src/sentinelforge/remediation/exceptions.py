"""SentinelForge Branch 2 — Remediation Exception Hierarchy.

Follows the pattern of agents/red/exceptions.py. All Branch 2 remediation
operations raise subclasses of RemediationException.
"""


class RemediationException(Exception):
    """Base exception for all Branch 2 remediation operations."""
    pass


class RemediationBudgetExhausted(RemediationException):
    """Raised when remediation budget limits are reached."""
    pass


class RemediationPolicyViolation(RemediationException):
    """Raised when a remediation proposal violates RemediationPolicy."""
    pass


class CloneCreationFailed(RemediationException):
    """Raised when an isolated clone cannot be created."""
    pass


class RollbackFailed(RemediationException):
    """Raised when a clone cannot be restored to a previous snapshot."""
    pass


class VulnerabilityClassificationError(RemediationException):
    """Raised when an observation cannot be classified as a vulnerability."""
    pass
