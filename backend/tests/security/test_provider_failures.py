"""SentinelForge — Provider Failure Handling Tests.

Verify that ALL provider failure modes result in safe behavior:
- No tool execution
- No unauthorized state transitions
- Evidence/audit recorded
- Deterministic failure state

Classification: SECURITY-VERIFIED
"""

import json
import pytest
from unittest.mock import MagicMock, patch
from uuid import uuid4

from sentinelforge.agents.red.exceptions import (
    ProviderAPIError,
    SchemaValidationError,
)
from sentinelforge.agents.red.provider import (
    FallbackProvider,
    MockProvider,
    OpenAICompatibleProvider,
    ProviderTimeoutError,
    RetryableProvider,
    ProviderRetryPolicy,
)
from sentinelforge.agents.red.schemas import RedAgentDecision, RedAgentBudget
from sentinelforge.domain.experiment import (
    ExperimentConstraints,
    RiskLevel,
    SecurityObjective,
)


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_objective():
    return SecurityObjective(
        objective_id=uuid4(),
        organization_id=uuid4(),
        title="Failure test",
        description="Test provider failure handling",
        target_system="sentinelforge-target",
    )


def _make_budget():
    return RedAgentBudget(max_iterations=2, max_experiments=1, max_llm_calls=5)


def _terminate_payload():
    return json.dumps({
        "decision": "TERMINATE_OBJECTIVE",
        "hypothesis": "test",
        "reasoning_summary": "test",
    })


def _propose_payload():
    return json.dumps({
        "decision": "PROPOSE_EXPERIMENT",
        "hypothesis": "test hypothesis",
        "reasoning_summary": "test reasoning",
        "scenario": {
            "title": "Test scenario",
            "strategy_description": "test strategy",
            "technique_ids": ["T1059.004"],
            "proposed_risk_level": "LOW",
            "proposed_actions": [{
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": ["-c", "whoami"],
                "technique_id": "T1059.004",
            }],
        },
        "expected_detection": {
            "should_detect": True,
            "expected_rule_category": "process_execution",
            "reason": "test",
        },
        "novelty_claim": {
            "category": "NOVEL",
            "differing_aspect": "test",
        },
    })


# ---------------------------------------------------------------------------
# Phase 10: Provider Failure Tests
# ---------------------------------------------------------------------------

class TestProviderTimeout:
    def test_timeout_raises_provider_timeout_error(self):
        def _timeout_post(url, payload):
            raise TimeoutError("socket timed out")

        provider = OpenAICompatibleProvider(
            model="test", http_post=_timeout_post
        )
        with pytest.raises(ProviderTimeoutError, match="timed out"):
            provider.generate(
                prompt="test", system_prompt="test"
            )

    def test_timeout_agent_terminates_gracefully(self):
        from sentinelforge.agents.red.agent import RedAgent, RedAgentConfig
        from sentinelforge.agents.red.novelty import NoveltyEvaluator
        from sentinelforge.agents.red.policies import SafetyBoundaryBridge

        def _timeout_post(url, payload):
            raise TimeoutError("connection timed out")

        provider = OpenAICompatibleProvider(
            model="test", http_post=_timeout_post
        )
        config = RedAgentConfig(
            provider=provider,
            budget=_make_budget(),
            constraints=ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM),
            bridge=SafetyBoundaryBridge(
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM)
            ),
            novelty=NoveltyEvaluator(),
        )
        agent = RedAgent(config)
        result = agent.run(_make_objective())

        assert result.final_state.value == "FINISHED"
        assert result.experiments == 0
        assert len(result.executed_blueprints) == 0


class TestProviderAPIError:
    def test_api_error_raises_provider_api_error(self):
        def _error_post(url, payload):
            raise ConnectionError("connection refused")

        provider = OpenAICompatibleProvider(
            model="test", http_post=_error_post
        )
        with pytest.raises(ProviderAPIError):
            provider.generate(prompt="test", system_prompt="test")

    def test_api_error_agent_terminates_gracefully(self):
        from sentinelforge.agents.red.agent import RedAgent, RedAgentConfig
        from sentinelforge.agents.red.novelty import NoveltyEvaluator
        from sentinelforge.agents.red.policies import SafetyBoundaryBridge

        def _error_post(url, payload):
            raise ConnectionError("connection refused")

        provider = OpenAICompatibleProvider(
            model="test", http_post=_error_post
        )
        config = RedAgentConfig(
            provider=provider,
            budget=_make_budget(),
            constraints=ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM),
            bridge=SafetyBoundaryBridge(
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM)
            ),
            novelty=NoveltyEvaluator(),
        )
        agent = RedAgent(config)
        result = agent.run(_make_objective())

        assert result.final_state.value == "FINISHED"
        assert result.experiments == 0


class TestMalformedOutput:
    def test_invalid_json_raises_schema_validation_error(self):
        provider = MockProvider(responses=["this is not json"])
        with pytest.raises(SchemaValidationError):
            provider.generate_structured(
                prompt="test",
                system_prompt="test",
                response_schema=RedAgentDecision,
            )

    def test_wrong_schema_fields_raises_schema_validation_error(self):
        provider = MockProvider(responses=[json.dumps({"wrong": "field"})])
        with pytest.raises(SchemaValidationError):
            provider.generate_structured(
                prompt="test",
                system_prompt="test",
                response_schema=RedAgentDecision,
            )

    def test_schema_retries_exhausted_agent_terminates(self):
        from sentinelforge.agents.red.agent import RedAgent, RedAgentConfig
        from sentinelforge.agents.red.novelty import NoveltyEvaluator
        from sentinelforge.agents.red.policies import SafetyBoundaryBridge

        # Always return invalid JSON
        provider = MockProvider(responses=["not json at all"] * 10)
        config = RedAgentConfig(
            provider=provider,
            budget=_make_budget(),
            constraints=ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM),
            bridge=SafetyBoundaryBridge(
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM)
            ),
            novelty=NoveltyEvaluator(),
            max_schema_retries=2,
        )
        agent = RedAgent(config)
        result = agent.run(_make_objective())

        assert result.final_state.value == "FINISHED"
        assert result.experiments == 0
        assert "schema retries" in result.terminated_reason.lower()


class TestRetryableProvider:
    def test_retries_on_provider_api_error(self):
        call_count = 0
        inner = MockProvider(responses=["valid json"])

        class _FailingProvider(MockProvider):
            def generate(self, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count <= 2:
                    raise ProviderAPIError("transient failure")
                return super().generate(**kwargs)

        retry_provider = RetryableProvider(
            inner=_FailingProvider(),
            policy=ProviderRetryPolicy(max_retries=3, backoff_base_seconds=0.01),
            sleep_fn=lambda x: None,
        )
        result = retry_provider.generate(
            prompt="test", system_prompt="test"
        )
        assert call_count == 3  # 2 failures + 1 success
        assert result is not None

    def test_retries_exhausted_raises(self):
        class _AlwaysFailingProvider(MockProvider):
            def generate(self, **kwargs):
                raise ProviderAPIError("persistent failure")

        retry_provider = RetryableProvider(
            inner=_AlwaysFailingProvider(),
            policy=ProviderRetryPolicy(max_retries=2, backoff_base_seconds=0.01),
            sleep_fn=lambda x: None,
        )
        with pytest.raises(ProviderAPIError, match="persistent failure"):
            retry_provider.generate(prompt="test", system_prompt="test")

    def test_no_retry_on_schema_validation_error(self):
        class _SchemaFailingProvider(MockProvider):
            def generate(self, **kwargs):
                raise SchemaValidationError("bad schema")

        retry_provider = RetryableProvider(
            inner=_SchemaFailingProvider(),
            policy=ProviderRetryPolicy(max_retries=3),
        )
        with pytest.raises(SchemaValidationError):
            retry_provider.generate(prompt="test", system_prompt="test")


class TestFallbackProvider:
    def test_fallback_skips_on_api_error(self):
        class _FailingProvider(MockProvider):
            def generate(self, **kwargs):
                raise ProviderAPIError("provider 1 down")

        fallback = FallbackProvider(providers=[
            _FailingProvider(),
            MockProvider(responses=["fallback success"]),
        ])
        result = fallback.generate(prompt="test", system_prompt="test")
        assert result == "fallback success"

    def test_all_providers_fail_raises(self):
        class _FailingProvider(MockProvider):
            def generate(self, **kwargs):
                raise ProviderAPIError("always fails")

        fallback = FallbackProvider(providers=[
            _FailingProvider(),
            _FailingProvider(),
        ])
        with pytest.raises(ProviderAPIError, match="all 2 provider"):
            fallback.generate(prompt="test", system_prompt="test")

    def test_no_retry_on_schema_error_across_providers(self):
        """Schema errors should NOT trigger fallback to next provider."""
        class _SchemaFailingProvider(MockProvider):
            def generate(self, **kwargs):
                raise SchemaValidationError("bad output")

        fallback = FallbackProvider(providers=[
            _SchemaFailingProvider(),
            MockProvider(responses=["should not reach"]),
        ])
        with pytest.raises(SchemaValidationError):
            fallback.generate(prompt="test", system_prompt="test")


class TestAgentProviderFailureIntegration:
    """Full agent loop with failing providers — verify safe termination."""

    def test_agent_terminates_on_all_provider_failures(self):
        from sentinelforge.agents.red.agent import RedAgent, RedAgentConfig
        from sentinelforge.agents.red.novelty import NoveltyEvaluator
        from sentinelforge.agents.red.policies import SafetyBoundaryBridge

        provider = MockProvider(fail_after=0)  # Always fails
        config = RedAgentConfig(
            provider=provider,
            budget=_make_budget(),
            constraints=ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM),
            bridge=SafetyBoundaryBridge(
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM)
            ),
            novelty=NoveltyEvaluator(),
        )
        agent = RedAgent(config)
        result = agent.run(_make_objective())

        assert result.final_state.value == "FINISHED"
        assert result.experiments == 0
        assert len(result.executed_blueprints) == 0

    def test_agent_records_failure_evidence(self):
        from sentinelforge.agents.red.agent import RedAgent, RedAgentConfig
        from sentinelforge.agents.red.novelty import NoveltyEvaluator
        from sentinelforge.agents.red.policies import SafetyBoundaryBridge

        provider = MockProvider(fail_after=0)
        config = RedAgentConfig(
            provider=provider,
            budget=_make_budget(),
            constraints=ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM),
            bridge=SafetyBoundaryBridge(
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.MEDIUM)
            ),
            novelty=NoveltyEvaluator(),
        )
        agent = RedAgent(config)
        result = agent.run(_make_objective())

        # Failure is recorded in terminated_reason
        assert result.terminated_reason
        assert len(result.terminated_reason) > 0
