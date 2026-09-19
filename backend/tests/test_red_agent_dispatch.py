"""Step 2A — Execution Dispatch.

Proves that the Red Agent's ONLY execution path is the existing
SimulationWorker / SimulationAdapter boundary. The agent never runs commands
itself; it forwards signed blueprints to the worker, and the worker is the
sole place a blueprint can be refused (invalid/expired/replayed/tampered) or
fail (infrastructure/target errors).

These tests are deterministic and do NOT require Docker (a fake adapter is
injected into a real SimulationWorker).
"""

import json
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.agents.red.agent import RedAgent, RedAgentConfig
from sentinelforge.agents.red.provider import MockProvider
from sentinelforge.agents.red.schemas import RedAgentBudget
from sentinelforge.agents.red.state import RedAgentState
from sentinelforge.db.models import Base, Organization
from sentinelforge.domain.experiment import SecurityObjective
from sentinelforge.domain.simulation import SimulationRequest
from sentinelforge.policy.signing import BlueprintSigner
from sentinelforge.simulation.adapter import SimulationAdapter
from sentinelforge.simulation.replay import SimulationRepository
from sentinelforge.simulation.worker import SimulationWorker

SIGNER_KEY = "sentinelforge-test-signing-key-not-for-production"
SIGNER_KEY_ID = "key1"
ORG_ID = uuid.UUID(int=0)


# ---------------------------------------------------------------------------
# Fixtures / helpers
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
        title="Linux Range Identity Recon",
        description="Explore detection coverage for identity reconnaissance.",
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
        "hypothesis": "whoami execution may not be detected by the range.",
        "reasoning_summary": "Basic recon may slip past current rules.",
        "scenario": {
            "title": "Identity Discovery via Shell",
            "strategy_description": "Run whoami to observe identity disclosure.",
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
            "reason": "Rule matches bash process creation.",
        },
        "novelty_claim": {
            "category": "NOVEL",
            "differing_aspect": "First identity recon attempt.",
        },
    }
    payload.update(overrides)
    return payload


def _terminate_payload():
    return {
        "decision": "TERMINATE_OBJECTIVE",
        "hypothesis": "Objective fully explored.",
        "reasoning_summary": "No new experiments remain.",
    }


def _signed_blueprint(signer, issued_at, expires_at):
    return signer.sign(
        blueprint_id=uuid.uuid4(),
        action_id=uuid.uuid4(),
        technique_id="T1059.004",
        target="sentinelforge-target",
        executable="/usr/bin/bash",
        arguments=["-c", "whoami"],
        run_as_user="labuser",
        issued_at=issued_at,
        expires_at=expires_at,
    )


# ---------------------------------------------------------------------------
# Allowed proposal -> dispatched through the worker
# ---------------------------------------------------------------------------
class TestAllowedDispatch:
    def test_allowed_proposal_dispatches_through_worker(self, session, objective):
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

        assert result.experiments == 1
        assert len(result.executed_blueprints) == 1
        assert len(result.simulation_executions) == 1
        execution = result.simulation_executions[0]
        assert execution.status == "COMPLETED"
        assert execution.stdout == "labuser"
        # The adapter — not the agent — is the only thing that ever executes.
        assert adapter.calls == [("/usr/bin/bash", ["-c", "whoami"], "labuser")]
        # The dispatched blueprint carries the worker's valid HMAC signature.
        assert worker.signer.verify(result.executed_blueprints[0]) is True

    def test_multiple_allowed_actions_all_dispatched(self, session, objective):
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
        payload["scenario"]["proposed_risk_level"] = "HIGH"
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

    def test_no_worker_no_dispatch(self, objective):
        """Without a worker the agent records the experiment but never executes."""
        provider = MockProvider(
            responses=[
                json.dumps(_valid_payload()),
                json.dumps(_terminate_payload()),
            ]
        )
        agent = RedAgent(RedAgentConfig(provider=provider))
        result = agent.run(objective)

        assert result.experiments == 1
        assert len(result.executed_blueprints) == 1
        assert result.simulation_executions == []


# ---------------------------------------------------------------------------
# Denied / invalid proposals -> zero execution
# ---------------------------------------------------------------------------
class TestZeroExecution:
    def test_denied_proposal_zero_execution(self, session, objective):
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
        assert result.final_state == RedAgentState.FINISHED

    def test_invalid_proposal_zero_execution(self, session, objective):
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)
        payload = _valid_payload()
        payload["reset_budget"] = True  # forbidden extra field -> schema rejected
        provider = MockProvider(responses=[json.dumps(payload)])
        agent = RedAgent(
            RedAgentConfig(
                provider=provider,
                worker=worker,
                budget=RedAgentBudget(max_llm_calls=3),
            )
        )
        result = agent.run(objective)

        assert result.experiments == 0
        assert result.executed_blueprints == []
        assert result.simulation_executions == []
        assert adapter.calls == []
        assert result.llm_calls == 3  # schema retries consumed, then aborted
        assert result.final_state == RedAgentState.FINISHED

    def test_unauthorized_target_zero_execution(self, session, objective):
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)
        payload = _valid_payload()
        payload["scenario"]["proposed_actions"][0]["target"] = "prod-db-server"
        provider = MockProvider(responses=[json.dumps(payload)])
        agent = RedAgent(RedAgentConfig(provider=provider, worker=worker))
        result = agent.run(objective)

        assert result.experiments == 0
        assert result.executed_blueprints == []
        assert result.simulation_executions == []
        assert adapter.calls == []

    def test_unauthorized_command_zero_execution(self, session, objective):
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)
        payload = _valid_payload()
        payload["scenario"]["proposed_actions"][0]["arguments"] = ["-c", "echo hacked"]
        provider = MockProvider(responses=[json.dumps(payload)])
        agent = RedAgent(RedAgentConfig(provider=provider, worker=worker))
        result = agent.run(objective)

        assert result.experiments == 0
        assert result.executed_blueprints == []
        assert result.simulation_executions == []
        assert adapter.calls == []


# ---------------------------------------------------------------------------
# Worker boundary: expired / replayed / tampered blueprints -> rejected
# ---------------------------------------------------------------------------
class TestWorkerBoundaryRejections:
    def test_worker_rejects_tampered_blueprint(self, session):
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)
        now = datetime.now(timezone.utc)
        bp = _signed_blueprint(worker.signer, now, now + timedelta(minutes=5))
        bp.target = "hacked-target"  # mutate after signing

        execution = worker.process(SimulationRequest(blueprint=bp))

        assert execution.status == "REJECTED"
        assert "INVALID_SIGNATURE" in (execution.failure_reason or "")
        assert adapter.calls == []

    def test_worker_rejects_expired_blueprint(self, session):
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)
        now = datetime.now(timezone.utc)
        bp = _signed_blueprint(worker.signer, now - timedelta(minutes=10), now - timedelta(minutes=5))

        execution = worker.process(SimulationRequest(blueprint=bp))

        assert execution.status == "REJECTED"
        assert "EXPIRED_BLUEPRINT" in (execution.failure_reason or "")
        assert adapter.calls == []

    def test_worker_rejects_replayed_blueprint(self, session):
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)
        now = datetime.now(timezone.utc)
        bp = _signed_blueprint(worker.signer, now, now + timedelta(minutes=5))

        first = worker.process(SimulationRequest(blueprint=bp))
        assert first.status == "COMPLETED"

        second = worker.process(SimulationRequest(blueprint=bp))
        assert second.status == "REJECTED"
        assert "REPLAY_DETECTED" in (second.failure_reason or "")
        # The adapter executed exactly once, despite the second dispatch attempt.
        assert adapter.calls == [("/usr/bin/bash", ["-c", "whoami"], "labuser")]

    def test_worker_rejects_unauthorized_command_after_signing(self, session):
        """Even a validly signed blueprint is refused by PolicyEngine at the worker."""
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)
        now = datetime.now(timezone.utc)
        bp = worker.signer.sign(
            blueprint_id=uuid.uuid4(),
            action_id=uuid.uuid4(),
            technique_id="T1059.004",
            target="sentinelforge-target",
            executable="/usr/bin/bash",
            arguments=["-c", "whoami; cat /etc/passwd"],
            run_as_user="labuser",
            issued_at=now,
            expires_at=now + timedelta(minutes=5),
        )

        execution = worker.process(SimulationRequest(blueprint=bp))

        assert execution.status == "REJECTED"
        assert "POLICY_DENIED" in (execution.failure_reason or "")
        assert adapter.calls == []


# ---------------------------------------------------------------------------
# Worker failure is fail-safe (design section 19)
# ---------------------------------------------------------------------------
class TestWorkerFailure:
    class RaisingWorker:
        def __init__(self):
            self.requests = []

        def process(self, request):
            self.requests.append(request)
            raise RuntimeError("target unreachable")

    def test_worker_failure_recorded_and_loop_continues(self, objective):
        worker = self.RaisingWorker()
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
        assert "target unreachable" in (result.simulation_executions[0].failure_reason or "")
        # Exactly one dispatch attempt was made.
        assert len(worker.requests) == 1
        assert result.final_state == RedAgentState.FINISHED