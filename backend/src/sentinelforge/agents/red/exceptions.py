"""Red Agent exception hierarchy.

SECURITY ROLE:
Exceptions in this module are raised ONLY by deterministic control-plane
code (state machine, safety bridge, budget monitor, novelty evaluator).
They must never be suppressed in a way that bypasses policy enforcement.
"""


class RedAgentException(Exception):
    """Base exception for all Red Agent operations."""


class SchemaValidationError(RedAgentException):
    """Raised when LLM output fails strict Pydantic schema validation."""


class SafetyRejectionError(RedAgentException):
    """Raised when a proposal is rejected by ExperimentSafetyBoundary / PolicyEngine."""


class NoveltyCheckError(RedAgentException):
    """Raised when a proposal cannot be evaluated for novelty (e.g. empty actions)."""


class BudgetExhaustedError(RedAgentException):
    """Raised when an LLM-controllable budget limit is reached."""


class ProviderAPIError(RedAgentException):
    """Raised when the configured LLM provider fails or is unavailable."""


class InvalidStateTransition(RedAgentException):
    """Raised when a state transition is not allowed by RedAgentStateMachine."""
