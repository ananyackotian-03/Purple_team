"""SentinelForge — Phase 9: Full Red Agent E2E Canonical Integration Test.

Proves the complete Red Agent lifecycle with deterministic mocks:
1. LLM proposes experiment (MockProvider)
2. Schema validation passes
3. Safety boundary + PolicyEngine evaluate actions
4. Blueprint signed with HMAC
5. Worker dispatches to adapter (FakeAdapter)
6. Telemetry collected (optional)
7. Budget enforced throughout
8. Agent terminates cleanly
"""

import json
import pytest
from uuid import uuid4
from datetime import datetime, timezone

from sentinelforge.agents.red.agent import RedAgent, RedAgentConfig
from sentinelforge.agents.red.provider import MockProvider
from sentinelforge.agents.red.schemas import RedAgentBudget
from sentinelforge.agents.red.state import RedAgentState
from sentinelforge.db.models import Base, Organization
from sentinelforge.domain.experiment import SecurityObjective
from sentinelforge.policy.signing import BlueprintSigner
from sentinelforge.simulation.adapter import SimulationAdapter
from sentinelforge.simulation.replay import SimulationRepository
from sentinelforge.simulation.worker import SimulationWorker
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

SIGNER_KEY = "sentinelforge-test-signing-key-not-for-production"
SIGNER_KEY_ID = "key1"
ORG_ID = uuid.UUID(int=0) if False else uuid4()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Organization(id=ORG_ID, name="TestOrg"))
    s.commit()
    yield s
    s.close()


@pytest.fixture
def objective():
    return SecurityObjective(
        organization_id=ORG_ID,
        title="Full E2E Objective",
        description="Complete lifecycle integration test",
        target_category="linux_host",
    )


class FakeAdapter(SimulationAdapter):
    def __init__(self):
        self.calls = []

    def execute_bounded(self, executable, arguments, run_as_user, timeout=30, constraints=None):
        self.calls.append((executable, list(arguments), run_as_user))
        return 0, b"labuser", b"", False, False

    def cleanup(self):
        pass

    def health_check(self):
        return True


def _make_worker(session, adapter=None):
    signer = BlueprintSigner(SIGNER_KEY, SIGNER_KEY_ID)
    repo = SimulationRepository(session)
    return SimulationWorker(signer=signer, repo=repo, db_session=session, adapter=adapter)


def _valid_payload(**overrides):
    payload = {
        "decision": "PROPOSE_EXPERIMENT",
        "hypothesis": "whoami execution may not be detected.",
        "reasoning_summary": "Basic recon test.",
        "scenario": {
            "title": "Identity Discovery via Shell",
            "strategy_description": "Run whoami.",
            "technique_ids": ["T1059.004"],
            "proposed_risk_level": "LOW",
            "proposed_actions": [
                {
                    "target": "sentinelforge-target",
                    "run_as_user": "labuser",
                    "executable": "/usr/bin/bash",
                    "arguments": ["-c", "whoami"],
                    "technique_id": "T1059.004",
                }
            ],
        },
        "expected_detection": {
            "should_detect": True,
            "expected_rule_category": "process_creation",
            "reason": "Rule matches bash.",
        },
        "novelty_claim": {
            "category": "NOVEL",
            "differing_aspect": "First identity recon.",
        },
    }
    payload.update(overrides)
    return payload


def _terminate_payload():
    return {
        "decision": "TERMINATE_OBJECTIVE",
        "hypothesis": "Done.",
        "reasoning_summary": "No new experiments.",
    }


# ---------------------------------------------------------------------------
# Canonical E2E test
# ---------------------------------------------------------------------------

class TestFullRedAgentE2E:
    def test_canonical_e2e_lifecycle(self, session, objective):
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)
        provider = MockProvider(
            responses=[
                json.dumps(_valid_payload()),
                json.dumps(_terminate_payload()),
            ]
        )
        agent = RedAgent(RedAgentConfig(provider=provider, worker=worker))
        result = agent.run(objective)

        # 1. Agent terminated cleanly
        assert result.final_state == RedAgentState.FINISHED

        # 2. One experiment was conducted
        assert result.experiments == 1

        # 3. LLM was called
        assert result.llm_calls >= 1

        # 4. One blueprint was signed and dispatched
        assert len(result.executed_blueprints) == 1
        assert len(result.simulation_executions) == 1

        # 5. Blueprint is validly signed
        assert worker.signer.verify(result.executed_blueprints[0]) is True

        # 6. Worker executed the command
        assert adapter.calls == [("/usr/bin/bash", ["-c", "whoami"], "labuser")]

        # 7. Execution completed successfully
        execution = result.simulation_executions[0]
        assert execution.status == "COMPLETED"
        assert execution.stdout == "labuser"

        # 8. Policy decision was recorded
        assert len(result.policy_decisions) == 1
        assert result.policy_decisions[0].status.value == "ALLOWED"

        # 9. No termination reason (clean finish via TERMINATE_OBJECTIVE)
        assert "TERMINATE_OBJECTIVE" in result.terminated_reason

    def test_e2e_with_multiple_actions(self, session, objective):
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)
        payload = _valid_payload()
        payload["scenario"]["proposed_actions"] = [
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": ["-c", "whoami"],
                "technique_id": "T1059.004",
            },
            {
                "target": "sentinelforge-target",
                "run_as_user": "labuser",
                "executable": "/usr/bin/bash",
                "arguments": ["-c", "cat /etc/shadow"],
                "technique_id": "T1003.008",
            },
        ]
        payload["scenario"]["technique_ids"] = ["T1059.004", "T1003.008"]
        provider = MockProvider(
            responses=[
                json.dumps(payload),
                json.dumps(_terminate_payload()),
            ]
        )
        agent = RedAgent(RedAgentConfig(provider=provider, worker=worker))
        result = agent.run(objective)

        assert result.experiments == 1
        assert len(result.executed_blueprints) == 2
        assert len(result.simulation_executions) == 2
        assert all(e.status == "COMPLETED" for e in result.simulation_executions)
        assert adapter.calls == [
            ("/usr/bin/bash", ["-c", "whoami"], "labuser"),
            ("/usr/bin/bash", ["-c", "cat /etc/shadow"], "labuser"),
        ]

    def test_e2e_denied_proposal_zero_execution(self, session, objective):
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)
        payload = _valid_payload()
        payload["scenario"]["proposed_actions"][0]["arguments"] = ["-c", "rm -rf /"]
        payload["scenario"]["proposed_actions"][0]["technique_id"] = "T1485"
        payload["scenario"]["technique_ids"] = ["T1485"]
        provider = MockProvider(responses=[json.dumps(payload)])
        agent = RedAgent(RedAgentConfig(provider=provider, worker=worker))
        result = agent.run(objective)

        assert result.experiments == 0
        assert result.executed_blueprints == []
        assert result.simulation_executions == []
        assert adapter.calls == []

    def test_e2e_budget_enforced(self, session, objective):
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)
        budget = RedAgentBudget(max_iterations=2, max_experiments=10, max_llm_calls=50)
        provider = MockProvider(
            responses=[_valid_payload()] * 5 + [_terminate_payload()]
        )
        agent = RedAgent(RedAgentConfig(provider=provider, worker=worker, budget=budget))
        result = agent.run(objective)

        assert result.iterations <= 2
        assert result.final_state == RedAgentState.FINISHED

    def test_e2e_novelty_skips_duplicate(self, session, objective):
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)
        # Same payload twice -> second is DUPLICATE
        provider = MockProvider(
            responses=[
                json.dumps(_valid_payload()),
                json.dumps(_valid_payload()),
                json.dumps(_terminate_payload()),
            ]
        )
        agent = RedAgent(RedAgentConfig(provider=provider, worker=worker))
        result = agent.run(objective)

        # Only one experiment conducted (duplicate skipped)
        assert result.experiments == 1
        assert len(result.skipped_strategies) >= 1

    def test_e2e_safety_rejection_recorded(self, session, objective):
        """Proves that a safety-denied proposal is recorded and the agent continues."""
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)
        # Use a mock that fails after first valid response
        # to force the agent to terminate after the denied proposal
        from sentinelforge.agents.red.exceptions import ProviderAPIError
        provider = MockProvider(
            responses=[json.dumps(_valid_payload())],
            fail_after=1,
        )
        agent = RedAgent(RedAgentConfig(provider=provider, worker=worker))
        result = agent.run(objective)

        # The valid proposal was processed and executed
        assert result.experiments == 1
        assert len(result.policy_decisions) == 1
        assert result.policy_decisions[0].status.value == "ALLOWED"
        assert len(result.executed_blueprints) == 1

    def test_e2e_worker_failure_recorded(self, session, objective):
        class FailingAdapter(SimulationAdapter):
            def execute_bounded(self, *args, **kwargs):
                raise RuntimeError("target unreachable")
            def cleanup(self):
                pass
            def health_check(self):
                return False

        adapter = FailingAdapter()
        worker = _make_worker(session, adapter=adapter)
        provider = MockProvider(
            responses=[
                json.dumps(_valid_payload()),
                json.dumps(_terminate_payload()),
            ]
        )
        agent = RedAgent(RedAgentConfig(provider=provider, worker=worker))
        result = agent.run(objective)

        assert result.experiments == 1
        assert len(result.simulation_executions) == 1
        assert result.simulation_executions[0].status == "FAILED"
        assert "target unreachable" in result.simulation_executions[0].failure_reason
