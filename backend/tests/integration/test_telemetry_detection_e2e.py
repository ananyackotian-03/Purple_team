"""Telemetry → Detection End-to-End Integration Tests.

Proves the complete pipeline:
    Red Agent → Experiment Execution → Telemetry Collection →
    Telemetry Normalization → Sigma Rule Evaluation → Detection Result →
    Evidence Correlation

Every test is deterministic (no network, no real LLM, no real Docker).
The tests verify that the architecture produces an attributable evidence
chain from experiment to detection.

Classification: TELEMETRY-DETECTION-VERIFIED
"""

import json
import os
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.agents.red.agent import RedAgent, RedAgentConfig
from sentinelforge.agents.red.novelty import NoveltyEvaluator
from sentinelforge.agents.red.policies import SafetyBoundaryBridge
from sentinelforge.agents.red.provider import MockProvider
from sentinelforge.agents.red.schemas import RedAgentBudget
from sentinelforge.db.models import Base, Organization
from sentinelforge.detection.collector import TelemetryCollector
from sentinelforge.detection.evaluator import (
    ActionDetectionOutcome,
    DetectionGapEvaluator,
    ScenarioDetectionOutcome,
)
from sentinelforge.detection.normalizer import NormalizedEvent, TelemetryNormalizer
from sentinelforge.detection.sigma_engine import DetectionOutcome, SigmaEngine
from sentinelforge.domain.experiment import (
    ExperimentConstraints,
    RiskLevel,
    SecurityObjective,
)
from sentinelforge.policy.signing import BlueprintSigner
from sentinelforge.simulation.adapter import SimulationAdapter
from sentinelforge.simulation.replay import SimulationRepository
from sentinelforge.simulation.worker import SimulationWorker

ORG_ID = uuid.uuid4()
RULES_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "src", "sentinelforge", "detection", "rules"
)


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
        title="Telemetry Detection E2E",
        description="End-to-end telemetry → detection pipeline verification",
        target_category="linux_host",
    )


@pytest.fixture
def sigma_engine():
    engine = SigmaEngine()
    engine.load_rules_from_directory(RULES_DIR)
    return engine


@pytest.fixture
def normalizer():
    return TelemetryNormalizer()


@pytest.fixture
def evaluator():
    return DetectionGapEvaluator()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

class FakeAdapter(SimulationAdapter):
    """Simulates a sandbox that produces deterministic stdout."""

    def __init__(self, stdout_text="labuser"):
        self.stdout_text = stdout_text
        self.calls = []

    def execute_bounded(self, executable, arguments, run_as_user, timeout=30, constraints=None):
        self.calls.append((executable, list(arguments), run_as_user))
        return 0, self.stdout_text.encode(), b"", False, False

    def cleanup(self):
        pass

    def health_check(self):
        return True


def _falco_json(**overrides):
    """Build a valid Falco JSON event."""
    fields = {
        "evt.type": "execve",
        "evt.hostname": "sentinelforge-host",
        "container.id": "abc123container",
        "container.name": "sentinelforge-target",
        "proc.name": "bash",
        "proc.exe": "/usr/bin/bash",
        "proc.cmdline": "bash -c whoami",
        "user.name": "labuser",
        "user.uid": 1000,
        "fd.name": "",
    }
    fields.update(overrides)
    return json.dumps({
        "time": "2026-08-14T10:00:00Z",
        "rule": "SentinelForge Telemetry Syscalls",
        "priority": "WARNING",
        "output": "Syscall event in target container",
        "output_fields": fields,
    })


def _shadow_falco_json():
    return _falco_json(**{
        "evt.type": "openat",
        "proc.name": "cat",
        "proc.exe": "/usr/bin/cat",
        "proc.cmdline": "cat /etc/shadow",
        "fd.name": "/etc/shadow",
    })


def _rm_falco_json():
    return _falco_json(**{
        "evt.type": "unlinkat",
        "proc.name": "rm",
        "proc.exe": "/usr/bin/rm",
        "proc.cmdline": "rm /tmp/sentinelforge_test_evidence.log",
        "fd.name": "/tmp/sentinelforge_test_evidence.log",
    })


def _valid_decision_payload():
    return {
        "decision": "PROPOSE_EXPERIMENT",
        "hypothesis": "Shell execution may not be detected",
        "reasoning_summary": "Basic recon test",
        "scenario": {
            "title": "Shell Execution Detection Test",
            "strategy_description": "Execute bash to verify detection coverage",
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
            "reason": "bash execution should be detected",
        },
        "novelty_claim": {
            "category": "NOVEL",
            "differing_aspect": "First shell execution test",
        },
    }


def _terminate_payload():
    return {
        "decision": "TERMINATE_OBJECTIVE",
        "hypothesis": "Done",
        "reasoning_summary": "Objective complete",
    }


def _make_worker(session, adapter=None):
    signer = BlueprintSigner("sentinelforge-secret-key-v1", "key1")
    repo = SimulationRepository(session)
    return SimulationWorker(signer=signer, repo=repo, db_session=session, adapter=adapter)


# ---------------------------------------------------------------------------
# Phase 2: Telemetry Schema Validation
# ---------------------------------------------------------------------------

class TestTelemetrySchemaValidation:
    def test_normalized_event_has_all_required_fields(self):
        normalizer = TelemetryNormalizer()
        ev = normalizer.normalize(_falco_json())
        assert ev is not None
        assert ev.event_id
        assert ev.correlation_id is None  # correlation is external
        assert ev.timestamp
        assert ev.source == "falco"
        assert ev.EventType  # non-empty
        assert ev.ProcessName  # non-empty
        assert ev.CommandLine  # non-empty
        assert ev.UserName  # non-empty
        assert ev.UserUid >= 0
        assert ev.ContainerName  # non-empty
        assert ev.raw_event_hash  # SHA-256

    def test_normalized_event_sigma_dict_has_matching_fields(self):
        normalizer = TelemetryNormalizer()
        ev = normalizer.normalize(_falco_json())
        sigma_dict = ev.to_sigma_dict()
        assert "EventType" in sigma_dict
        assert "ProcessName" in sigma_dict
        assert "CommandLine" in sigma_dict
        assert "UserName" in sigma_dict
        assert "TargetFile" in sigma_dict

    def test_malformed_json_returns_none(self):
        normalizer = TelemetryNormalizer()
        assert normalizer.normalize("{bad json") is None

    def test_oversized_event_returns_none(self):
        normalizer = TelemetryNormalizer()
        big = _falco_json(**{"proc.name": "A" * 70000})
        assert normalizer.normalize(big) is None

    def test_empty_output_fields_returns_none(self):
        normalizer = TelemetryNormalizer()
        bare = json.dumps({"time": "2026-08-14T10:00:00Z", "output_fields": {}})
        assert normalizer.normalize(bare) is None


# ---------------------------------------------------------------------------
# Phase 3: Telemetry Normalization
# ---------------------------------------------------------------------------

class TestTelemetryNormalization:
    def test_falco_field_mapping(self, normalizer):
        ev = normalizer.normalize(_falco_json())
        assert ev.ProcessName == "bash"
        assert ev.Executable == "/usr/bin/bash"
        assert ev.CommandLine == "bash -c whoami"
        assert ev.UserName == "labuser"
        assert ev.UserUid == 1000
        assert ev.ContainerName == "sentinelforge-target"

    def test_control_chars_stripped(self, normalizer):
        dirty = _falco_json(**{"proc.name": "bash\x00\x01", "proc.cmdline": "whoami\x07"})
        ev = normalizer.normalize(dirty)
        assert ev is not None
        assert "\x00" not in ev.ProcessName
        assert "\x01" not in ev.ProcessName
        assert "\x07" not in ev.CommandLine

    def test_unicode_nfc_normalization(self, normalizer):
        decomposed = "cafe\u0301"
        ev = normalizer.normalize(_falco_json(**{"proc.cmdline": decomposed}))
        assert ev is not None
        assert ev.CommandLine == "caf\u00e9"

    def test_deterministic_hash(self, normalizer):
        raw = _falco_json()
        ev1 = normalizer.normalize(raw)
        ev2 = normalizer.normalize(raw)
        assert ev1.raw_event_hash == ev2.raw_event_hash
        assert ev1.event_id != ev2.event_id  # unique event IDs


# ---------------------------------------------------------------------------
# Phase 4: Sigma Rule Evaluation (Detection Engine)
# ---------------------------------------------------------------------------

class TestSigmaDetection:
    def test_rules_loaded(self, sigma_engine):
        assert sigma_engine.rule_count >= 3

    def test_shell_execution_detected(self, sigma_engine, normalizer):
        ev = normalizer.normalize(_falco_json())
        results = sigma_engine.evaluate(ev.to_sigma_dict(), event_id=ev.event_id)
        matched = [r for r in results if r.matched]
        assert any(r.rule_id == "sentinelforge-shell-execution" for r in matched)

    def test_shadow_access_detected(self, sigma_engine, normalizer):
        ev = normalizer.normalize(_shadow_falco_json())
        results = sigma_engine.evaluate(ev.to_sigma_dict(), event_id=ev.event_id)
        matched = [r for r in results if r.matched]
        assert any(r.rule_id == "sentinelforge-shadow-access" for r in matched)

    def test_file_deletion_detected(self, sigma_engine, normalizer):
        ev = normalizer.normalize(_rm_falco_json())
        results = sigma_engine.evaluate(ev.to_sigma_dict(), event_id=ev.event_id)
        matched = [r for r in results if r.matched]
        assert any(r.rule_id == "sentinelforge-file-deletion" for r in matched)

    def test_unrelated_event_no_match(self, sigma_engine, normalizer):
        ev = normalizer.normalize(_falco_json(**{"proc.name": "sshd", "proc.cmdline": "sshd: session"}))
        results = sigma_engine.evaluate(ev.to_sigma_dict(), event_id=ev.event_id)
        matched = [r for r in results if r.matched]
        assert len(matched) == 0

    def test_detection_result_has_all_fields(self, sigma_engine, normalizer):
        ev = normalizer.normalize(_falco_json())
        results = sigma_engine.evaluate(ev.to_sigma_dict(), event_id=ev.event_id, correlation_id="test-corr")
        assert len(results) >= 3
        for r in results:
            assert r.detection_id
            assert r.correlation_id == "test-corr"
            assert r.technique_id
            assert r.rule_id
            assert isinstance(r.matched, bool)
            assert r.outcome in (DetectionOutcome.DETECTED, DetectionOutcome.EVENT_NO_MATCH)
            assert r.timestamp
            assert r.source == "sigma"


# ---------------------------------------------------------------------------
# Phase 5: Detection Gap Evaluator (Correlation)
# ---------------------------------------------------------------------------

class TestDetectionGapEvaluator:
    def test_detected_action(self, evaluator, sigma_engine, normalizer):
        from sentinelforge.domain.action_ir import ActionIR, ActionType

        ev = normalizer.normalize(_falco_json())
        ev.correlation_id = "test-scenario-1"
        action = ActionIR(
            action_id=uuid.uuid4(),
            blueprint_id=uuid.uuid4(),
            technique_id="T1059.004",
            action_type=ActionType.PROCESS_EXEC,
            executable="/usr/bin/bash",
            arguments=["-c", "whoami"],
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc),
        )
        outcome = evaluator.evaluate_action(action, [ev], sigma_engine, correlation_id="test-scenario-1")
        assert outcome.outcome == DetectionOutcome.DETECTED
        assert "sentinelforge-shell-execution" in outcome.matched_rule_ids
        assert ev.event_id in outcome.evidence_event_ids

    def test_detection_gap_no_telemetry(self, evaluator, sigma_engine):
        from sentinelforge.domain.action_ir import ActionIR, ActionType

        action = ActionIR(
            action_id=uuid.uuid4(),
            blueprint_id=uuid.uuid4(),
            technique_id="T1059.004",
            action_type=ActionType.PROCESS_EXEC,
            executable="/usr/bin/bash",
            arguments=["-c", "whoami"],
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc),
        )
        outcome = evaluator.evaluate_action(action, [], sigma_engine, correlation_id="test-scenario-1")
        assert outcome.outcome == DetectionOutcome.DETECTION_GAP

    def test_scenario_all_detected(self, evaluator, sigma_engine, normalizer):
        from sentinelforge.domain.action_ir import ActionIR, ActionType

        ev = normalizer.normalize(_falco_json())
        ev.correlation_id = "test-scenario-2"
        action = ActionIR(
            action_id=uuid.uuid4(),
            blueprint_id=uuid.uuid4(),
            technique_id="T1059.004",
            action_type=ActionType.PROCESS_EXEC,
            executable="/usr/bin/bash",
            arguments=["-c", "whoami"],
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc),
        )
        outcome = evaluator.evaluate_scenario(
            scenario_id="test-scenario-2",
            actions=[action],
            events=[ev],
            sigma_engine=sigma_engine,
            organization_id=str(ORG_ID),
        )
        assert outcome.overall_outcome == DetectionOutcome.DETECTED
        assert len(outcome.gap_action_ids) == 0

    def test_scenario_detection_gap(self, evaluator, sigma_engine):
        from sentinelforge.domain.action_ir import ActionIR, ActionType

        action = ActionIR(
            action_id=uuid.uuid4(),
            blueprint_id=uuid.uuid4(),
            technique_id="T1059.004",
            action_type=ActionType.PROCESS_EXEC,
            executable="/usr/bin/bash",
            arguments=["-c", "whoami"],
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc),
        )
        outcome = evaluator.evaluate_scenario(
            scenario_id="test-scenario-3",
            actions=[action],
            events=[],
            sigma_engine=sigma_engine,
            organization_id=str(ORG_ID),
        )
        assert outcome.overall_outcome == DetectionOutcome.DETECTION_GAP
        assert len(outcome.gap_action_ids) == 1

    def test_correlation_id_isolation(self, evaluator, sigma_engine, normalizer):
        from sentinelforge.domain.action_ir import ActionIR, ActionType

        ev_a = normalizer.normalize(_falco_json())
        ev_a.correlation_id = "scenario-A"
        ev_b = normalizer.normalize(_falco_json())
        ev_b.correlation_id = "scenario-B"

        action = ActionIR(
            action_id=uuid.uuid4(),
            blueprint_id=uuid.uuid4(),
            technique_id="T1059.004",
            action_type=ActionType.PROCESS_EXEC,
            executable="/usr/bin/bash",
            arguments=["-c", "whoami"],
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc),
        )
        # Events from scenario-B should be isolated when evaluating scenario-A
        outcome = evaluator.evaluate_action(action, [ev_a, ev_b], sigma_engine, correlation_id="scenario-A")
        assert outcome.outcome == DetectionOutcome.DETECTED
        # Only ev_a should be in evidence (ev_b is from different scenario)
        assert ev_a.event_id in outcome.evidence_event_ids
        assert ev_b.event_id not in outcome.evidence_event_ids


# ---------------------------------------------------------------------------
# Phase 6: Red Agent → Telemetry → Detection E2E
# ---------------------------------------------------------------------------

class TestRedAgentTelemetryDetectionE2E:
    def test_red_agent_collects_telemetry_and_detects(self, session, objective, sigma_engine):
        """Full pipeline: Red Agent → Worker → Telemetry → Sigma → Detection."""
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)

        def telemetry_source(execution):
            return [_falco_json()]

        collector = TelemetryCollector(TelemetryNormalizer(), sigma_engine, redis_client=None)
        evaluator = DetectionGapEvaluator()

        provider = MockProvider(responses=[
            json.dumps(_valid_decision_payload()),
            json.dumps(_terminate_payload()),
        ])

        agent = RedAgent(
            RedAgentConfig(
                provider=provider,
                budget=RedAgentBudget(max_iterations=2, max_experiments=1, max_llm_calls=5),
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW),
                bridge=SafetyBoundaryBridge(
                    constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW)
                ),
                novelty=NoveltyEvaluator(),
                worker=worker,
                detection_evaluator=evaluator,
                sigma_engine=sigma_engine,
                telemetry_collector=collector,
                telemetry_source=telemetry_source,
                db_session=session,
            )
        )

        result = agent.run(objective)

        # Red Agent completed
        assert result.final_state.value in ("FINISHED", "WAIT")
        assert result.experiments == 1

        # Telemetry was collected
        assert len(result.collected_telemetry) >= 1
        ev = result.collected_telemetry[0]
        assert isinstance(ev, NormalizedEvent)
        assert ev.ProcessName == "bash"

        # Correlation chain: blueprint_id → correlation_id
        assert ev.correlation_id == str(result.executed_blueprints[0].blueprint_id)

        # Detection outcome was produced
        assert result.detection_outcome is not None
        assert isinstance(result.detection_outcome, ScenarioDetectionOutcome)
        assert result.detection_outcome.overall_outcome == DetectionOutcome.DETECTED

        # Detection result has evidence
        assert len(result.detection_outcome.action_outcomes) >= 1
        action_outcome = result.detection_outcome.action_outcomes[0]
        assert action_outcome.outcome == DetectionOutcome.DETECTED
        assert "sentinelforge-shell-execution" in action_outcome.matched_rule_ids
        assert ev.event_id in action_outcome.evidence_event_ids

    def test_red_agent_detection_gap_when_no_telemetry(self, session, objective, sigma_engine):
        """When no telemetry is produced, detection outcome is DETECTION_GAP."""
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)

        # Telemetry source returns empty (simulates sandbox without Falco)
        def telemetry_source(execution):
            return []

        collector = TelemetryCollector(TelemetryNormalizer(), sigma_engine, redis_client=None)
        evaluator = DetectionGapEvaluator()

        provider = MockProvider(responses=[
            json.dumps(_valid_decision_payload()),
            json.dumps(_terminate_payload()),
        ])

        agent = RedAgent(
            RedAgentConfig(
                provider=provider,
                budget=RedAgentBudget(max_iterations=2, max_experiments=1, max_llm_calls=5),
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW),
                bridge=SafetyBoundaryBridge(
                    constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW)
                ),
                novelty=NoveltyEvaluator(),
                worker=worker,
                detection_evaluator=evaluator,
                sigma_engine=sigma_engine,
                telemetry_collector=collector,
                telemetry_source=telemetry_source,
                db_session=session,
            )
        )

        result = agent.run(objective)

        assert result.final_state.value in ("FINISHED", "WAIT")
        assert result.experiments == 1
        assert len(result.collected_telemetry) == 0

        # Detection gap because no telemetry
        assert result.detection_outcome is not None
        assert isinstance(result.detection_outcome, ScenarioDetectionOutcome)
        assert result.detection_outcome.overall_outcome == DetectionOutcome.DETECTION_GAP

    def test_red_agent_untrusted_telemetry_detection(self, session, objective, sigma_engine):
        """Detection via explicit untrusted_telemetry (external Falco source)."""
        worker = _make_worker(session, adapter=FakeAdapter())
        evaluator = DetectionGapEvaluator()

        provider = MockProvider(responses=[
            json.dumps(_valid_decision_payload()),
            json.dumps(_terminate_payload()),
        ])

        agent = RedAgent(
            RedAgentConfig(
                provider=provider,
                budget=RedAgentBudget(max_iterations=2, max_experiments=1, max_llm_calls=5),
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW),
                bridge=SafetyBoundaryBridge(
                    constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW)
                ),
                novelty=NoveltyEvaluator(),
                worker=worker,
                detection_evaluator=evaluator,
                sigma_engine=sigma_engine,
            )
        )

        # Provide external telemetry
        result = agent.run(objective, untrusted_telemetry=[_falco_json()])

        assert result.final_state.value in ("FINISHED", "WAIT")
        assert result.detection_outcome is not None
        assert result.detection_outcome.overall_outcome == DetectionOutcome.DETECTED


# ---------------------------------------------------------------------------
# Phase 7: Correlation Chain Verification
# ---------------------------------------------------------------------------

class TestCorrelationChain:
    def test_experiment_to_telemetry_correlation(self, session, objective, sigma_engine):
        """experiment_id → blueprint_id → correlation_id → telemetry event."""
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)

        def telemetry_source(execution):
            return [_falco_json()]

        collector = TelemetryCollector(TelemetryNormalizer(), sigma_engine, redis_client=None)

        provider = MockProvider(responses=[
            json.dumps(_valid_decision_payload()),
            json.dumps(_terminate_payload()),
        ])

        agent = RedAgent(
            RedAgentConfig(
                provider=provider,
                budget=RedAgentBudget(max_iterations=2, max_experiments=1, max_llm_calls=5),
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW),
                bridge=SafetyBoundaryBridge(
                    constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW)
                ),
                novelty=NoveltyEvaluator(),
                worker=worker,
                telemetry_collector=collector,
                telemetry_source=telemetry_source,
            )
        )

        result = agent.run(objective)

        # Verify the correlation chain
        assert len(result.executed_blueprints) == 1
        bp = result.executed_blueprints[0]

        assert len(result.collected_telemetry) == 1
        ev = result.collected_telemetry[0]

        # blueprint.blueprint_id → correlation_id
        assert ev.correlation_id == str(bp.blueprint_id)
        # blueprint.technique_id → action.technique_id
        assert bp.technique_id == "T1059.004"

    def test_telemetry_to_detection_correlation(self, session, objective, sigma_engine):
        """Telemetry event_id → DetectionResult.evidence_event_ids."""
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)

        def telemetry_source(execution):
            return [_falco_json()]

        collector = TelemetryCollector(TelemetryNormalizer(), sigma_engine, redis_client=None)
        evaluator = DetectionGapEvaluator()

        provider = MockProvider(responses=[
            json.dumps(_valid_decision_payload()),
            json.dumps(_terminate_payload()),
        ])

        agent = RedAgent(
            RedAgentConfig(
                provider=provider,
                budget=RedAgentBudget(max_iterations=2, max_experiments=1, max_llm_calls=5),
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW),
                bridge=SafetyBoundaryBridge(
                    constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW)
                ),
                novelty=NoveltyEvaluator(),
                worker=worker,
                detection_evaluator=evaluator,
                sigma_engine=sigma_engine,
                telemetry_collector=collector,
                telemetry_source=telemetry_source,
            )
        )

        result = agent.run(objective)

        assert result.detection_outcome is not None
        ev = result.collected_telemetry[0]
        action_outcome = result.detection_outcome.action_outcomes[0]

        # event_id in evidence_event_ids
        assert ev.event_id in action_outcome.evidence_event_ids
        # technique_id propagated
        assert action_outcome.technique_id == "T1059.004"

    def test_detection_result_to_evidence_correlation(self, session, objective, sigma_engine):
        """Detection outcome contains rule_id, technique_id, and evidence for audit."""
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)

        def telemetry_source(execution):
            return [_falco_json()]

        collector = TelemetryCollector(TelemetryNormalizer(), sigma_engine, redis_client=None)
        evaluator = DetectionGapEvaluator()

        provider = MockProvider(responses=[
            json.dumps(_valid_decision_payload()),
            json.dumps(_terminate_payload()),
        ])

        agent = RedAgent(
            RedAgentConfig(
                provider=provider,
                budget=RedAgentBudget(max_iterations=2, max_experiments=1, max_llm_calls=5),
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW),
                bridge=SafetyBoundaryBridge(
                    constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW)
                ),
                novelty=NoveltyEvaluator(),
                worker=worker,
                detection_evaluator=evaluator,
                sigma_engine=sigma_engine,
                telemetry_collector=collector,
                telemetry_source=telemetry_source,
                db_session=session,
            )
        )

        result = agent.run(objective)

        # Verify evidence is fully traceable
        outcome = result.detection_outcome
        assert outcome.scenario_id  # scenario link
        assert outcome.organization_id == str(ORG_ID)  # tenant link
        for ao in outcome.action_outcomes:
            assert ao.technique_id  # ATT&CK link
            assert ao.matched_rule_ids  # Sigma rule link
            assert ao.evidence_event_ids  # telemetry link


# ---------------------------------------------------------------------------
# Phase 8: Detection Gap Tracking
# ---------------------------------------------------------------------------

class TestDetectionGapTracking:
    def test_gap_recorded_when_rule_missing(self, session, objective, sigma_engine):
        """When telemetry exists but no Sigma rule matches, gap is recorded."""
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)

        def telemetry_source(execution):
            # Return event for a process with no matching Sigma rule
            return [_falco_json(**{"evt.type": "connect", "proc.name": "sshd", "proc.cmdline": "sshd: session for labuser", "fd.name": "192.168.1.1:22"})]

        collector = TelemetryCollector(TelemetryNormalizer(), sigma_engine, redis_client=None)
        evaluator = DetectionGapEvaluator()

        # Use allowed command (whoami) so safety boundary passes,
        # but telemetry doesn't match any detection rule for T1059.004
        provider = MockProvider(responses=[
            json.dumps(_valid_decision_payload()),
            json.dumps(_terminate_payload()),
        ])

        agent = RedAgent(
            RedAgentConfig(
                provider=provider,
                budget=RedAgentBudget(max_iterations=2, max_experiments=1, max_llm_calls=5),
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW),
                bridge=SafetyBoundaryBridge(
                    constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW)
                ),
                novelty=NoveltyEvaluator(),
                worker=worker,
                detection_evaluator=evaluator,
                sigma_engine=sigma_engine,
                telemetry_collector=collector,
                telemetry_source=telemetry_source,
            )
        )

        result = agent.run(objective)

        assert result.detection_outcome is not None
        # Telemetry exists but doesn't match shell execution rule → NOT_DETECTED
        assert result.detection_outcome.overall_outcome != DetectionOutcome.DETECTED


# ---------------------------------------------------------------------------
# Phase 9: Evidence Integration
# ---------------------------------------------------------------------------

class TestEvidenceIntegration:
    def test_full_evidence_chain(self, session, objective, sigma_engine):
        """Objective → Experiment → Execution → Telemetry → Detection → Evidence."""
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)

        def telemetry_source(execution):
            return [_falco_json()]

        collector = TelemetryCollector(TelemetryNormalizer(), sigma_engine, redis_client=None)
        evaluator = DetectionGapEvaluator()

        provider = MockProvider(responses=[
            json.dumps(_valid_decision_payload()),
            json.dumps(_terminate_payload()),
        ])

        agent = RedAgent(
            RedAgentConfig(
                provider=provider,
                budget=RedAgentBudget(max_iterations=2, max_experiments=1, max_llm_calls=5),
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW),
                bridge=SafetyBoundaryBridge(
                    constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW)
                ),
                novelty=NoveltyEvaluator(),
                worker=worker,
                detection_evaluator=evaluator,
                sigma_engine=sigma_engine,
                telemetry_collector=collector,
                telemetry_source=telemetry_source,
                db_session=session,
            )
        )

        result = agent.run(objective)

        # 1. Objective exists
        assert result.objective.objective_id == objective.objective_id
        assert result.objective.organization_id == ORG_ID

        # 2. Experiment executed
        assert result.experiments == 1
        assert len(result.executed_blueprints) == 1

        # 3. Execution completed
        assert len(result.simulation_executions) == 1
        assert result.simulation_executions[0].status == "COMPLETED"

        # 4. Telemetry collected
        assert len(result.collected_telemetry) == 1
        ev = result.collected_telemetry[0]
        assert isinstance(ev, NormalizedEvent)

        # 5. Detection evaluated
        assert result.detection_outcome is not None
        assert result.detection_outcome.overall_outcome == DetectionOutcome.DETECTED

        # 6. Evidence is linked
        outcome = result.detection_outcome
        assert outcome.scenario_id
        assert outcome.organization_id == str(ORG_ID)
        assert len(outcome.action_outcomes) >= 1
        assert outcome.action_outcomes[0].matched_rule_ids
        assert outcome.action_outcomes[0].evidence_event_ids


# ---------------------------------------------------------------------------
# Phase 10: Security Requirements
# ---------------------------------------------------------------------------

class TestSecurityRequirements:
    def test_telemetry_does_not_modify_agent_budget(self, session, objective, sigma_engine):
        """Telemetry collection cannot alter agent budget."""
        budget = RedAgentBudget(max_iterations=2, max_experiments=1, max_llm_calls=5)
        original_max = budget.max_iterations

        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)

        def telemetry_source(execution):
            return [_falco_json()]

        collector = TelemetryCollector(TelemetryNormalizer(), sigma_engine, redis_client=None)

        provider = MockProvider(responses=[
            json.dumps(_valid_decision_payload()),
            json.dumps(_terminate_payload()),
        ])

        agent = RedAgent(
            RedAgentConfig(
                provider=provider,
                budget=budget,
                constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW),
                bridge=SafetyBoundaryBridge(
                    constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW)
                ),
                novelty=NoveltyEvaluator(),
                worker=worker,
                telemetry_collector=collector,
                telemetry_source=telemetry_source,
            )
        )

        agent.run(objective)
        assert budget.max_iterations == original_max

    def test_telemetry_does_not_modify_policy(self, session, objective, sigma_engine):
        """Telemetry events cannot alter safety constraints."""
        constraints = ExperimentConstraints(max_risk_level=RiskLevel.LOW)
        original_risk = constraints.max_risk_level

        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)

        def telemetry_source(execution):
            return [_falco_json()]

        collector = TelemetryCollector(TelemetryNormalizer(), sigma_engine, redis_client=None)

        provider = MockProvider(responses=[
            json.dumps(_valid_decision_payload()),
            json.dumps(_terminate_payload()),
        ])

        agent = RedAgent(
            RedAgentConfig(
                provider=provider,
                budget=RedAgentBudget(max_iterations=2, max_experiments=1, max_llm_calls=5),
                constraints=constraints,
                bridge=SafetyBoundaryBridge(constraints=constraints),
                novelty=NoveltyEvaluator(),
                worker=worker,
                telemetry_collector=collector,
                telemetry_source=telemetry_source,
            )
        )

        agent.run(objective)
        assert constraints.max_risk_level == original_risk

    def test_malformed_telemetry_does_not_crash_detection(self, sigma_engine):
        """Malformed telemetry is rejected before detection evaluation."""
        normalizer = TelemetryNormalizer()
        evaluator = DetectionGapEvaluator()

        bad_events = [
            None,
            "not a NormalizedEvent",
            42,
            {"fake": "data"},
        ]

        from sentinelforge.domain.action_ir import ActionIR, ActionType
        action = ActionIR(
            action_id=uuid.uuid4(),
            blueprint_id=uuid.uuid4(),
            technique_id="T1059.004",
            action_type=ActionType.PROCESS_EXEC,
            executable="/usr/bin/bash",
            arguments=["-c", "whoami"],
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc),
        )

        # Should not crash — evaluator skips non-NormalizedEvent items
        outcome = evaluator.evaluate_action(action, bad_events, sigma_engine, correlation_id="test")
        assert outcome.outcome == DetectionOutcome.DETECTION_GAP  # no valid telemetry

    def test_no_docker_access_in_telemetry_modules(self):
        """Telemetry modules must not import docker or simulation."""
        import sentinelforge.detection.normalizer as nm
        import sentinelforge.detection.collector as cl
        import sentinelforge.detection.sigma_engine as se
        import sentinelforge.detection.evaluator as ev

        for mod in (nm, cl, se, ev):
            src = __import__("inspect").getsource(mod)
            assert "import docker" not in src
            assert "from docker" not in src
            assert "DockerSocket" not in src
            assert "docker.sock" not in src


# ---------------------------------------------------------------------------
# Phase 11: Bounded Processing
# ---------------------------------------------------------------------------

class TestBoundedProcessing:
    def test_telemetry_size_bounded(self):
        """Oversized telemetry is rejected before detection."""
        normalizer = TelemetryNormalizer()
        big = _falco_json(**{"proc.name": "A" * 70000})
        ev = normalizer.normalize(big)
        assert ev is None

    def test_detection_result_count_bounded(self, sigma_engine, normalizer):
        """Detection produces exactly one result per loaded rule per event."""
        ev = normalizer.normalize(_falco_json())
        results = sigma_engine.evaluate(ev.to_sigma_dict(), event_id=ev.event_id)
        assert len(results) == sigma_engine.rule_count

    def test_collector_stream_bounded(self):
        """Stream processing handles arbitrary input without crash."""
        normalizer = TelemetryNormalizer()
        engine = SigmaEngine()
        engine.load_rules_from_directory(RULES_DIR)
        collector = TelemetryCollector(normalizer, engine, redis_client=None)

        lines = [
            _falco_json(),
            _shadow_falco_json(),
            _rm_falco_json(),
            "{invalid",
            "",
            "x" * 100000,
            json.dumps({"time": "2026", "output_fields": {}}),
        ]
        stats = collector.process_stream(iter(lines))
        assert stats["events_processed"] >= 3
        assert stats["events_rejected"] >= 1


# ---------------------------------------------------------------------------
# Tenant Isolation
# ---------------------------------------------------------------------------

class TestTelemetryDetectionTenantIsolation:
    def test_detection_events_isolated_by_correlation_id(self, sigma_engine, evaluator, normalizer):
        """Events from different scenarios do not leak across correlation IDs."""
        from sentinelforge.domain.action_ir import ActionIR, ActionType

        ev_a = normalizer.normalize(_falco_json())
        ev_a.correlation_id = "org-a-scenario-1"
        ev_b = normalizer.normalize(_falco_json())
        ev_b.correlation_id = "org-b-scenario-2"

        action = ActionIR(
            action_id=uuid.uuid4(),
            blueprint_id=uuid.uuid4(),
            technique_id="T1059.004",
            action_type=ActionType.PROCESS_EXEC,
            executable="/usr/bin/bash",
            arguments=["-c", "whoami"],
            issued_at=datetime.now(timezone.utc),
            expires_at=datetime.now(timezone.utc),
        )

        # Evaluate for org-a: only ev_a should be evidence
        outcome_a = evaluator.evaluate_action(action, [ev_a, ev_b], sigma_engine, correlation_id="org-a-scenario-1")
        assert ev_a.event_id in outcome_a.evidence_event_ids
        assert ev_b.event_id not in outcome_a.evidence_event_ids

        # Evaluate for org-b: only ev_b should be evidence
        outcome_b = evaluator.evaluate_action(action, [ev_a, ev_b], sigma_engine, correlation_id="org-b-scenario-2")
        assert ev_b.event_id in outcome_b.evidence_event_ids
        assert ev_a.event_id not in outcome_b.evidence_event_ids
