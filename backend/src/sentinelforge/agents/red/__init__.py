"""SentinelForge Red Agent V1 package.

The Red Agent is an LLM-driven adversarial scenario generator operating
STRICTLY below the deterministic safety control plane. Every proposed action
must pass ExperimentSafetyBoundary and PolicyEngine evaluation before any
SignedBlueprint is produced or executed.

Trust tiers:
- Tier 1 (untrusted): LLM providers, model output, raw telemetry.
- Tier 2 (authoritative): PolicyEngine, ExperimentSafetyBoundary,
  BlueprintSigner, RedAgentStateMachine.
- Tier 3 (isolated): sentinelforge-target container.

This package exposes only the orchestrator entry point (RedAgent) plus the
core decision schema. All internal modules are imported explicitly.
"""

from sentinelforge.agents.red.agent import RedAgent, RedAgentConfig, RedAgentRunResult
from sentinelforge.agents.red.exceptions import (
    BudgetExhaustedError,
    InvalidStateTransition,
    NoveltyCheckError,
    ProviderAPIError,
    RedAgentException,
    SafetyRejectionError,
    SchemaValidationError,
)
from sentinelforge.agents.red.novelty import (
    NoveltyEvaluator,
    NoveltyStatus,
    StrategyFingerprint,
)
from sentinelforge.agents.red.policies import SafetyBoundaryBridge, SafetyBridgeResult
from sentinelforge.agents.red.provider import (
    AnthropicProvider,
    FallbackProvider,
    GeminiProvider,
    LLMProvider,
    MockProvider,
    OpenAICompatibleProvider,
    OpenAIProvider,
    ProviderRetryPolicy,
    ProviderTimeoutError,
    RetryableProvider,
)
from sentinelforge.agents.red.schemas import (
    ActionProposalSpec,
    ExpectedDetectionSpec,
    NoveltyClaimSpec,
    RedAgentBudget,
    RedAgentDecision,
    ScenarioProposalSpec,
)
from sentinelforge.agents.red.state import RedAgentState, RedAgentStateMachine

__all__ = [
    "RedAgent",
    "RedAgentConfig",
    "RedAgentRunResult",
    "RedAgentException",
    "SchemaValidationError",
    "SafetyRejectionError",
    "NoveltyCheckError",
    "BudgetExhaustedError",
    "ProviderAPIError",
    "InvalidStateTransition",
    "ActionProposalSpec",
    "ScenarioProposalSpec",
    "ExpectedDetectionSpec",
    "NoveltyClaimSpec",
    "RedAgentDecision",
    "RedAgentBudget",
    "LLMProvider",
    "MockProvider",
    "OpenAICompatibleProvider",
    "OpenAIProvider",
    "AnthropicProvider",
    "GeminiProvider",
    "ProviderRetryPolicy",
    "ProviderTimeoutError",
    "RetryableProvider",
    "FallbackProvider",
    "StrategyFingerprint",
    "NoveltyStatus",
    "NoveltyEvaluator",
    "SafetyBoundaryBridge",
    "SafetyBridgeResult",
    "RedAgentState",
    "RedAgentStateMachine",
]