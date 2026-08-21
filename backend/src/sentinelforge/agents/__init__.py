"""SentinelForge Agents Package."""

from sentinelforge.agents.red_agent import RedAgentPlanner, PlanResult, STRATEGY_CATALOG
from sentinelforge.agents.blue_agent import (
    BlueAgentAnalyst,
    GapAnalysisResult,
    SigmaRuleValidator,
    RuleValidationSandbox,
    RetestOrchestrator,
)
from sentinelforge.agents.red import (
    RedAgent,
    RedAgentConfig,
    RedAgentDecision,
    RedAgentStateMachine,
)

__all__ = [
    "RedAgentPlanner",
    "PlanResult",
    "STRATEGY_CATALOG",
    "BlueAgentAnalyst",
    "GapAnalysisResult",
    "SigmaRuleValidator",
    "RuleValidationSandbox",
    "RetestOrchestrator",
    "RedAgent",
    "RedAgentConfig",
    "RedAgentDecision",
    "RedAgentStateMachine",
]

