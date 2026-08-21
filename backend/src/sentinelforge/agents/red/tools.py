"""RedAgentToolRegistry — safe application-level tools exposed to the LLM.

SECURITY ROLE:
The LLM may only invoke tools registered in this registry. Registry-managed
tools are read-only queries or proposal submissions within the agent's own
tenant scope. Dangerous tool names (shell, docker, filesystem, policy,
signing, database admin) are hard-rejected at registration time.
"""

from typing import Any, Callable, Dict, List, Optional

from sentinelforge.agents.red.exceptions import RedAgentException

# Tool names the LLM is explicitly FORBIDDEN from using.
_FORBIDDEN_TOOLS = frozenset(
    {
        "docker_exec",
        "execute_shell",
        "arbitrary_command",
        "host_filesystem",
        "docker_socket",
        "modify_policy",
        "get_hmac_key",
        "modify_falco",
        "modify_sigma",
        "modify_database",
        "reset_budget",
    }
)

# Authorized read-only / proposal-submission tool contract.
AUTHORIZED_TOOLS: List[str] = [
    "get_security_objective",
    "get_environment",
    "get_experiment_history",
    "get_detection_coverage",
    "get_detection_gaps",
    "get_previous_strategy_results",
    "propose_experiment",
    "get_experiment_status",
    "get_experiment_result",
]


class ToolNotAllowedError(RedAgentException):
    """Raised when a tool name is forbidden or not registered."""


class RedAgentToolRegistry:
    """Whitelist-based tool registry.

    Implementations are plain Python callables bound by the orchestrator.
    Tools are NOT shell/docker/filesystem primitives.
    """

    def __init__(self):
        self._implementations: Dict[str, Callable[..., Any]] = {}

    @property
    def tool_names(self) -> List[str]:
        return sorted(self._implementations)

    def register(self, name: str, implementation: Callable[..., Any]) -> None:
        """Register a tool implementation.

        Raises:
            ToolNotAllowedError: If the name is forbidden or not in the
                authorized tool contract.
        """
        if name in _FORBIDDEN_TOOLS:
            raise ToolNotAllowedError(f"tool {name!r} is forbidden for the Red Agent")
        if name not in AUTHORIZED_TOOLS:
            raise ToolNotAllowedError(
                f"tool {name!r} is not in the authorized tool contract"
            )
        self._implementations[name] = implementation

    def invoke(self, name: str, **kwargs: Any) -> Any:
        """Invoke a registered tool by name.

        Raises:
            ToolNotAllowedError: If the tool is not registered or forbidden.
        """
        if name in _FORBIDDEN_TOOLS or name not in AUTHORIZED_TOOLS:
            raise ToolNotAllowedError(f"tool {name!r} is not callable by the Red Agent")
        implementation = self._implementations.get(name)
        if implementation is None:
            raise ToolNotAllowedError(f"tool {name!r} has no registered implementation")
        return implementation(**kwargs)