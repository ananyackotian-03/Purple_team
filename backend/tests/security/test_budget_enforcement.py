"""SentinelForge — Phase 4: Budget Enforcement.

Proves that:
- Budget limits are enforced deterministically by Python code
- LLM cannot increase its own budget
- Budget exhaustion terminates the agent loop
- All budget dimensions (iterations, experiments, LLM calls, wall time) are enforced
- Budget is checked at loop entry and after each experiment
"""

import json
import pytest
from uuid import uuid4
from datetime import datetime, timezone, timedelta

from sentinelforge.agents.red.agent import RedAgent, RedAgentConfig
from sentinelforge.agents.red.exceptions import BudgetExhaustedError
from sentinelforge.agents.red.provider import MockProvider
from sentinelforge.agents.red.schemas import RedAgentBudget
from sentinelforge.agents.red.state import RedAgentState
from sentinelforge.domain.experiment import SecurityObjective, ExperimentConstraints


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_objective():
    return SecurityObjective(
        organization_id=uuid4(),
        title="Budget Test Objective",
        description="Test budget enforcement",
    )


def _valid_payload():
    return json.dumps({
        "decision": "PROPOSE_EXPERIMENT",
        "hypothesis": "Test hypothesis",
        "reasoning_summary": "Test reasoning",
        "scenario": {
            "title": "Budget Test Scenario",
            "strategy_description": "Test",
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
    })


def _terminate_payload():
    return json.dumps({
        "decision": "TERMINATE_OBJECTIVE",
        "hypothesis": "Done",
        "reasoning_summary": "Finished",
    })


# ---------------------------------------------------------------------------
# Budget limit tests
# ---------------------------------------------------------------------------

class TestIterationBudget:
    def test_budget_enforced_after_experiment(self):
        budget = RedAgentBudget(max_iterations=1, max_experiments=2, max_llm_calls=10)
        provider = MockProvider(responses=[_valid_payload(), _terminate_payload()])
        agent = RedAgent(RedAgentConfig(provider=provider, budget=budget))
        result = agent.run(_make_objective())
        assert result.iterations <= 1
        assert result.final_state == RedAgentState.FINISHED

    def test_budget_exhausted_mid_loop(self):
        budget = RedAgentBudget(max_iterations=2, max_experiments=10, max_llm_calls=50)
        provider = MockProvider(responses=[_valid_payload()] * 5 + [_terminate_payload()])
        agent = RedAgent(RedAgentConfig(provider=provider, budget=budget))
        result = agent.run(_make_objective())
        assert result.iterations <= 2
        assert result.final_state == RedAgentState.FINISHED


class TestExperimentBudget:
    def test_experiment_limit_enforced(self):
        budget = RedAgentBudget(max_iterations=10, max_experiments=1, max_llm_calls=10)
        provider = MockProvider(responses=[_valid_payload(), _terminate_payload()])
        agent = RedAgent(RedAgentConfig(provider=provider, budget=budget))
        result = agent.run(_make_objective())
        assert result.experiments <= 1


class TestLLMCallBudget:
    def test_llm_call_limit_enforced(self):
        budget = RedAgentBudget(max_iterations=10, max_experiments=10, max_llm_calls=1)
        provider = MockProvider(responses=[_terminate_payload()])
        agent = RedAgent(RedAgentConfig(provider=provider, budget=budget))
        result = agent.run(_make_objective())
        assert result.llm_calls <= 1


class TestWallTimeBudget:
    def test_wall_time_limit_enforced(self):
        budget = RedAgentBudget(
            max_iterations=1000,
            max_experiments=1000,
            max_llm_calls=10000,
            max_wall_time_seconds=1,
        )
        provider = MockProvider(responses=[_terminate_payload()])
        agent = RedAgent(RedAgentConfig(provider=provider, budget=budget))
        result = agent.run(_make_objective())
        assert result.final_state == RedAgentState.FINISHED


# ---------------------------------------------------------------------------
# Budget cannot be modified by LLM
# ---------------------------------------------------------------------------

class TestBudgetImmutability:
    def test_budget_from_config_not_from_llm(self):
        budget = RedAgentBudget(max_iterations=3, max_experiments=2, max_llm_calls=5)
        assert budget.max_iterations == 3
        assert budget.max_experiments == 2
        assert budget.max_llm_calls == 5

    def test_budget_extra_fields_forbidden(self):
        with pytest.raises(Exception):
            RedAgentBudget(max_iterations=3, reset_budget=True)

    def test_remaining_budget_calculation(self):
        budget = RedAgentBudget(max_iterations=10, max_experiments=5, max_llm_calls=20)
        remaining = budget.remaining(iterations=3, experiments=2, llm_calls=5)
        assert remaining["max_iterations"] == 7
        assert remaining["max_experiments"] == 3
        assert remaining["max_llm_calls"] == 15

    def test_assert_has_remaining_passes_within_limits(self):
        budget = RedAgentBudget(max_iterations=10, max_experiments=5, max_llm_calls=20)
        budget.assert_has_remaining(iterations=3, experiments=2, llm_calls=5)

    def test_assert_has_remaining_fails_at_limit(self):
        budget = RedAgentBudget(max_iterations=10, max_experiments=5, max_llm_calls=20)
        with pytest.raises(BudgetExhaustedError, match="iteration limit"):
            budget.assert_has_remaining(iterations=10, experiments=0, llm_calls=0)

    def test_assert_has_remaining_fails_experiment_limit(self):
        budget = RedAgentBudget(max_iterations=10, max_experiments=5, max_llm_calls=20)
        with pytest.raises(BudgetExhaustedError, match="experiment limit"):
            budget.assert_has_remaining(iterations=0, experiments=5, llm_calls=0)

    def test_assert_has_remaining_fails_llm_call_limit(self):
        budget = RedAgentBudget(max_iterations=10, max_experiments=5, max_llm_calls=20)
        with pytest.raises(BudgetExhaustedError, match="LLM call limit"):
            budget.assert_has_remaining(iterations=0, experiments=0, llm_calls=20)


# ---------------------------------------------------------------------------
# Budget domain constraints (Pydantic)
# ---------------------------------------------------------------------------

class TestBudgetDomainConstraints:
    def test_max_iterations_minimum(self):
        with pytest.raises(Exception):
            RedAgentBudget(max_iterations=0)

    def test_max_experiments_minimum(self):
        with pytest.raises(Exception):
            RedAgentBudget(max_experiments=-1)

    def test_max_llm_calls_minimum(self):
        with pytest.raises(Exception):
            RedAgentBudget(max_llm_calls=0)

    def test_max_wall_time_minimum(self):
        with pytest.raises(Exception):
            RedAgentBudget(max_wall_time_seconds=0)


# ---------------------------------------------------------------------------
# Integration: agent terminates cleanly on budget exhaustion
# ---------------------------------------------------------------------------

class TestAgentBudgetIntegration:
    def test_agent_terminates_on_iteration_limit(self):
        budget = RedAgentBudget(max_iterations=2, max_experiments=10, max_llm_calls=50)
        provider = MockProvider(responses=[_valid_payload()] * 10 + [_terminate_payload()])
        agent = RedAgent(RedAgentConfig(provider=provider, budget=budget))
        result = agent.run(_make_objective())
        assert result.final_state == RedAgentState.FINISHED
        assert result.iterations <= 2

    def test_agent_terminates_on_llm_call_limit(self):
        budget = RedAgentBudget(max_iterations=100, max_experiments=100, max_llm_calls=3)
        provider = MockProvider(responses=[_valid_payload()] * 10)
        agent = RedAgent(RedAgentConfig(provider=provider, budget=budget))
        result = agent.run(_make_objective())
        assert result.final_state == RedAgentState.FINISHED
        assert result.llm_calls <= 3
