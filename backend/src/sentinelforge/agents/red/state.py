"""RedAgentStateMachine — deterministic state transitions.

SECURITY ROLE:
The LLM NEVER controls state transitions. All transitions are governed by
deterministic Python code in the orchestrator. Any attempt to perform a
transition that is not explicitly permitted raises InvalidStateTransition,
so no LLM output can force the agent into an executing state.
"""

from enum import Enum
from typing import Dict, FrozenSet, Set

from sentinelforge.agents.red.exceptions import InvalidStateTransition


class RedAgentState(str, Enum):
    """All states the Red Agent may occupy during a single objective run."""

    IDLE = "IDLE"
    OBJECTIVE_RECEIVED = "OBJECTIVE_RECEIVED"
    CONTEXT_LOADING = "CONTEXT_LOADING"
    ANALYZING = "ANALYZING"
    HYPOTHESIS_GENERATED = "HYPOTHESIS_GENERATED"
    SCENARIO_GENERATED = "SCENARIO_GENERATED"
    NOVELTY_CHECK = "NOVELTY_CHECK"
    SAFETY_SUBMITTED = "SAFETY_SUBMITTED"
    DENIED = "DENIED"
    ESCALATED = "ESCALATED"
    ALLOWED = "ALLOWED"
    EXECUTING = "EXECUTING"
    OBSERVING = "OBSERVING"
    EVALUATING = "EVALUATING"
    LEARNING = "LEARNING"
    REFINE = "REFINE"
    WAIT = "WAIT"
    CONTINUE = "CONTINUE"
    FINISHED = "FINISHED"


# Valid transition table. Only these edges are permitted.
_TRANSITIONS: Dict[RedAgentState, Set[RedAgentState]] = {
    RedAgentState.IDLE: {RedAgentState.OBJECTIVE_RECEIVED},
    RedAgentState.OBJECTIVE_RECEIVED: {RedAgentState.CONTEXT_LOADING},
    RedAgentState.CONTEXT_LOADING: {RedAgentState.ANALYZING},
    RedAgentState.ANALYZING: {
        RedAgentState.HYPOTHESIS_GENERATED,
        RedAgentState.CONTINUE,
        RedAgentState.FINISHED,
    },
    RedAgentState.HYPOTHESIS_GENERATED: {RedAgentState.SCENARIO_GENERATED, RedAgentState.FINISHED},
    RedAgentState.SCENARIO_GENERATED: {RedAgentState.NOVELTY_CHECK},
    RedAgentState.NOVELTY_CHECK: {
        RedAgentState.SAFETY_SUBMITTED,
        RedAgentState.REFINE,
        RedAgentState.FINISHED,
    },
    RedAgentState.SAFETY_SUBMITTED: {
        RedAgentState.DENIED,
        RedAgentState.ESCALATED,
        RedAgentState.ALLOWED,
    },
    RedAgentState.DENIED: {RedAgentState.REFINE, RedAgentState.FINISHED},
    RedAgentState.ESCALATED: {RedAgentState.WAIT},
    RedAgentState.WAIT: {RedAgentState.ANALYZING, RedAgentState.FINISHED},
    RedAgentState.ALLOWED: {RedAgentState.EXECUTING},
    RedAgentState.EXECUTING: {RedAgentState.OBSERVING},
    RedAgentState.OBSERVING: {RedAgentState.EVALUATING},
    RedAgentState.EVALUATING: {RedAgentState.LEARNING},
    RedAgentState.LEARNING: {RedAgentState.ANALYZING, RedAgentState.CONTINUE, RedAgentState.FINISHED},
    RedAgentState.REFINE: {RedAgentState.ANALYZING},
    RedAgentState.CONTINUE: {RedAgentState.ANALYZING, RedAgentState.FINISHED},
    RedAgentState.FINISHED: set(),
}


class RedAgentStateMachine:
    """Strict, deterministic state machine with transition guards."""

    def __init__(self, initial_state: RedAgentState = RedAgentState.IDLE):
        self._state = initial_state
        self._history: list[RedAgentState] = [initial_state]

    @property
    def state(self) -> RedAgentState:
        return self._state

    @property
    def history(self) -> list[RedAgentState]:
        return list(self._history)

    def can_transition(self, target: RedAgentState) -> bool:
        """Return True if a transition to `target` is currently permitted."""
        return target in _TRANSITIONS.get(self._state, frozenset())

    def allowed_transitions(self) -> FrozenSet[RedAgentState]:
        """Return the set of states reachable from the current state."""
        return frozenset(_TRANSITIONS.get(self._state, set()))

    def transition(self, target: RedAgentState) -> RedAgentState:
        """Transition to `target`, enforcing the transition table.

        Raises:
            InvalidStateTransition: When the transition is not permitted.
        """
        if not self.can_transition(target):
            raise InvalidStateTransition(
                f"Invalid transition {self._state.value} -> {target.value}"
            )
        self._state = target
        self._history.append(target)
        return self._state

    def reset(self) -> None:
        """Return the machine to IDLE and clear history."""
        self._state = RedAgentState.IDLE
        self._history = [RedAgentState.IDLE]