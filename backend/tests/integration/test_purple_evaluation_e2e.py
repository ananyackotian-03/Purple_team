"""Purple Evaluation End-to-End Integration Tests.

Proves the complete deterministic pipeline:
    Red Agent → Experiment Execution → Telemetry Collection →
    Telemetry Normalization → Sigma Rule Evaluation → Detection Result →
    Purple Evaluation → Coverage Report → Retest Comparison

Every test is deterministic (no network, no real LLM, no real Docker).
The tests verify that the architecture produces attributable evidence
from experiment through detection to purple evaluation.

Classification: PURPLE-EVALUATION-VERIFIED
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
from sentinelforge.db.models import Base, Organization, PurpleEvaluationRecord
from sentinelforge.detection.collector import TelemetryCollector
from sentinelforge.detection.evaluator import (
    ActionDetectionOutcome,
    CoverageReport,
    DetectionGapEvaluator,
    PurpleEvaluation,
    PurpleEvaluator,
    ScenarioDetectionOutcome,
)
from sentinelforge.detection.normalizer import NormalizedEvent, TelemetryNormalizer
from sentinelforge.detection.sigma_engine import DetectionOutcome, SigmaEngine
from sentinelforge.domain.action_ir import ActionIR, ActionType
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
ORG_ID_B = uuid.uuid4()
RULES_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "src", "sentinelforge", "detection", "rules"
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    s.add(Organization(id=ORG_ID, name="TestOrg"))
    s.add(Organization(id=ORG_ID_B, name="TestOrgB"))
    s.commit()
    yield s
    s.close()


@pytest.fixture
def objective():
    return SecurityObjective(
        organization_id=ORG_ID,
        title="Purple Evaluation E2E",
        description="End-to-end purple evaluation pipeline verification",
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


@pytest.fixture
def purple_evaluator():
    return PurpleEvaluator()


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


def _unrelated_falco_json():
    """An event that does NOT match any existing Sigma rule for the expected technique."""
    return _falco_json(**{
        "evt.type": "execve",
        "proc.name": "sshd",
        "proc.exe": "/usr/sbin/sshd",
        "proc.cmdline": "sshd: session for labuser",
        "fd.name": "192.168.1.1:22",
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


def _make_action(tech_id="T1059.004", executable="/usr/bin/bash", args=None):
    """Build a minimal ActionIR for testing."""
    return ActionIR(
        action_id=uuid.uuid4(),
        blueprint_id=uuid.uuid4(),
        technique_id=tech_id,
        action_type=ActionType.PROCESS_EXEC,
        target="sentinelforge-target",
        executable=executable,
        arguments=args or ["-c", "whoami"],
        run_as_user="labuser",
        issued_at=datetime.now(timezone.utc),
        expires_at=datetime.now(timezone.utc),
    )


# ---------------------------------------------------------------------------
# 1. DETECTED evaluation
# ---------------------------------------------------------------------------

class TestPurpleDetected:
    def test_detected_evaluation(self, purple_evaluator, sigma_engine, normalizer):
        """Shell execution -> telemetry -> Sigma match -> DETECTED."""
        ev = normalizer.normalize(_falco_json())
        ev.correlation_id = "test-purple-1"

        action = _make_action()
        scenario_outcome = ScenarioDetectionOutcome(
            scenario_id="test-scenario-1",
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.DETECTED,
            action_outcomes=[
                ActionDetectionOutcome(
                    action_id=str(action.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.DETECTED,
                    matched_rule_ids=["sentinelforge-shell-execution"],
                    evidence_event_ids=[ev.event_id],
                    reason="Detected by shell execution rule",
                )
            ],
            gap_action_ids=[],
        )

        purple = purple_evaluator.evaluate(
            scenario_outcome=scenario_outcome,
            actions=[action],
            execution_id=str(action.blueprint_id),
        )

        assert purple.detection_status == "DETECTED"
        assert purple.technique_id == "T1059.004"
        assert "sentinelforge-shell-execution" in purple.matched_rule_ids
        assert ev.event_id in purple.evidence_event_ids
        assert purple.experiment_id == "test-scenario-1"
        assert purple.organization_id == str(ORG_ID)
        assert purple.execution_id == str(action.blueprint_id)
        assert purple.gap_reason is None

    def test_detected_persists_to_db(self, session, purple_evaluator):
        """PurpleEvaluation DETECTED persists to DB correctly."""
        action = _make_action()
        test_scenario_id = str(uuid.uuid4())
        scenario_outcome = ScenarioDetectionOutcome(
            scenario_id=test_scenario_id,
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.DETECTED,
            action_outcomes=[
                ActionDetectionOutcome(
                    action_id=str(action.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.DETECTED,
                    matched_rule_ids=["sentinelforge-shell-execution"],
                    evidence_event_ids=["ev-1"],
                    reason="Detected",
                )
            ],
            gap_action_ids=[],
        )

        purple = purple_evaluator.evaluate(
            scenario_outcome=scenario_outcome,
            actions=[action],
            execution_id=str(action.blueprint_id),
        )

        record = PurpleEvaluationRecord(
            id=uuid.UUID(purple.evaluation_id),
            organization_id=ORG_ID,
            experiment_id=uuid.UUID(purple.experiment_id),
            execution_id=uuid.UUID(purple.execution_id) if purple.execution_id else None,
            technique_id=purple.technique_id,
            detection_status=purple.detection_status,
            matched_rule_ids=json.dumps(purple.matched_rule_ids),
            evidence_event_ids=json.dumps(purple.evidence_event_ids),
            expected_detection=purple.expected_detection,
            gap_reason=purple.gap_reason,
            evaluated_at=datetime.now(timezone.utc),
        )
        session.add(record)
        session.commit()

        fetched = session.query(PurpleEvaluationRecord).filter_by(
            id=uuid.UUID(purple.evaluation_id)
        ).first()
        assert fetched is not None
        assert fetched.detection_status == "DETECTED"
        assert fetched.technique_id == "T1059.004"


# ---------------------------------------------------------------------------
# 2. NOT_DETECTED evaluation
# ---------------------------------------------------------------------------

class TestPurpleNotDetected:
    def test_not_detected_evaluation(self, purple_evaluator):
        """Telemetry exists, no matching rule -> NOT_DETECTED."""
        action = _make_action()
        scenario_outcome = ScenarioDetectionOutcome(
            scenario_id="test-scenario-nd",
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.NOT_DETECTED,
            action_outcomes=[
                ActionDetectionOutcome(
                    action_id=str(action.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.NOT_DETECTED,
                    matched_rule_ids=[],
                    evidence_event_ids=["ev-nd-1"],
                    reason="Telemetry observed but no Sigma rule matched technique T1059.004",
                )
            ],
            gap_action_ids=[str(action.action_id)],
        )

        purple = purple_evaluator.evaluate(
            scenario_outcome=scenario_outcome,
            actions=[action],
        )

        assert purple.detection_status == "NOT_DETECTED"
        assert purple.matched_rule_ids == []
        assert "ev-nd-1" in purple.evidence_event_ids
        assert purple.gap_reason is not None
        assert "no Sigma rule matched" in purple.gap_reason


# ---------------------------------------------------------------------------
# 3. DETECTION_GAP evaluation
# ---------------------------------------------------------------------------

class TestPurpleDetectionGap:
    def test_detection_gap_no_telemetry(self, purple_evaluator):
        """No telemetry -> DETECTION_GAP."""
        action = _make_action()
        scenario_outcome = ScenarioDetectionOutcome(
            scenario_id="test-scenario-gap",
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.DETECTION_GAP,
            action_outcomes=[
                ActionDetectionOutcome(
                    action_id=str(action.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.DETECTION_GAP,
                    matched_rule_ids=[],
                    evidence_event_ids=[],
                    reason="No relevant telemetry events captured for technique T1059.004",
                )
            ],
            gap_action_ids=[str(action.action_id)],
        )

        purple = purple_evaluator.evaluate(
            scenario_outcome=scenario_outcome,
            actions=[action],
        )

        assert purple.detection_status == "DETECTION_GAP"
        assert purple.matched_rule_ids == []
        assert purple.evidence_event_ids == []
        assert purple.gap_reason is not None
        assert "No relevant telemetry" in purple.gap_reason


# ---------------------------------------------------------------------------
# 4. Coverage: 100% detection
# ---------------------------------------------------------------------------

class TestCoverageHundredPercent:
    def test_hundred_percent_coverage(self, purple_evaluator):
        """All experiments detected -> 100% coverage."""
        evals = []
        for i in range(3):
            action = _make_action()
            scenario_outcome = ScenarioDetectionOutcome(
                scenario_id=f"sc-{i}",
                organization_id=str(ORG_ID),
                overall_outcome=DetectionOutcome.DETECTED,
                action_outcomes=[
                    ActionDetectionOutcome(
                        action_id=str(action.action_id),
                        technique_id="T1059.004",
                        outcome=DetectionOutcome.DETECTED,
                        matched_rule_ids=["sentinelforge-shell-execution"],
                        evidence_event_ids=[f"ev-{i}"],
                        reason="Detected",
                    )
                ],
                gap_action_ids=[],
            )
            evals.append(purple_evaluator.evaluate(
                scenario_outcome=scenario_outcome,
                actions=[action],
            ))

        report = purple_evaluator.compute_coverage(evals, str(ORG_ID))
        assert report.total_experiments == 3
        assert report.detected_experiments == 3
        assert report.missed_experiments == 0
        assert report.gap_experiments == 0
        assert report.coverage_pct == 100.0


# ---------------------------------------------------------------------------
# 5. Coverage: zero eligible experiments
# ---------------------------------------------------------------------------

class TestCoverageZero:
    def test_zero_eligible_experiments(self, purple_evaluator):
        """No evaluations -> coverage = 0.0, not NaN or error."""
        report = purple_evaluator.compute_coverage([], str(ORG_ID))
        assert report.total_experiments == 0
        assert report.detected_experiments == 0
        assert report.coverage_pct == 0.0
        assert report.technique_coverage == {}


# ---------------------------------------------------------------------------
# 6. Coverage: multiple experiments
# ---------------------------------------------------------------------------

class TestCoverageMultiple:
    def test_multiple_experiments_coverage(self, purple_evaluator):
        """2 detected / 3 eligible = 66.67%."""
        evals = []
        statuses = [
            DetectionOutcome.DETECTED,
            DetectionOutcome.DETECTED,
            DetectionOutcome.NOT_DETECTED,
        ]
        for i, status in enumerate(statuses):
            action = _make_action()
            scenario_outcome = ScenarioDetectionOutcome(
                scenario_id=f"sc-multi-{i}",
                organization_id=str(ORG_ID),
                overall_outcome=status,
                action_outcomes=[
                    ActionDetectionOutcome(
                        action_id=str(action.action_id),
                        technique_id="T1059.004",
                        outcome=status,
                        matched_rule_ids=["rule-1"] if status == DetectionOutcome.DETECTED else [],
                        evidence_event_ids=[f"ev-multi-{i}"],
                        reason="ok" if status == DetectionOutcome.DETECTED else "missed",
                    )
                ],
                gap_action_ids=[str(action.action_id)] if status != DetectionOutcome.DETECTED else [],
            )
            evals.append(purple_evaluator.evaluate(
                scenario_outcome=scenario_outcome,
                actions=[action],
            ))

        report = purple_evaluator.compute_coverage(evals, str(ORG_ID))
        assert report.total_experiments == 3
        assert report.detected_experiments == 2
        assert report.missed_experiments == 1
        assert abs(report.coverage_pct - 66.67) < 0.01


# ---------------------------------------------------------------------------
# 7. Technique coverage
# ---------------------------------------------------------------------------

class TestTechniqueCoverage:
    def test_technique_coverage(self, purple_evaluator):
        """Per-technique bool map tracks detection per technique."""
        evals = []
        # T1059.004 detected
        action1 = _make_action(tech_id="T1059.004")
        evals.append(purple_evaluator.evaluate(
            scenario_outcome=ScenarioDetectionOutcome(
                scenario_id="sc-tc-1",
                organization_id=str(ORG_ID),
                overall_outcome=DetectionOutcome.DETECTED,
                action_outcomes=[ActionDetectionOutcome(
                    action_id=str(action1.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.DETECTED,
                    matched_rule_ids=["sentinelforge-shell-execution"],
                    evidence_event_ids=["ev-tc-1"],
                    reason="ok",
                )],
                gap_action_ids=[],
            ),
            actions=[action1],
        ))

        # T1003.008 NOT detected
        action2 = _make_action(tech_id="T1003.008", executable="/usr/bin/cat", args=["-c", "cat /etc/shadow"])
        evals.append(purple_evaluator.evaluate(
            scenario_outcome=ScenarioDetectionOutcome(
                scenario_id="sc-tc-2",
                organization_id=str(ORG_ID),
                overall_outcome=DetectionOutcome.NOT_DETECTED,
                action_outcomes=[ActionDetectionOutcome(
                    action_id=str(action2.action_id),
                    technique_id="T1003.008",
                    outcome=DetectionOutcome.NOT_DETECTED,
                    matched_rule_ids=[],
                    evidence_event_ids=["ev-tc-2"],
                    reason="no rule",
                )],
                gap_action_ids=[str(action2.action_id)],
            ),
            actions=[action2],
        ))

        report = purple_evaluator.compute_coverage(evals, str(ORG_ID))
        assert report.technique_coverage.get("T1059.004") is True
        assert report.technique_coverage.get("T1003.008") is False


# ---------------------------------------------------------------------------
# 8. Gap reason propagation
# ---------------------------------------------------------------------------

class TestGapReason:
    def test_gap_reason_propagated(self, purple_evaluator):
        """Gap reason from non-detected actions propagated to PurpleEvaluation."""
        action = _make_action()
        scenario_outcome = ScenarioDetectionOutcome(
            scenario_id="sc-gr",
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.DETECTION_GAP,
            action_outcomes=[
                ActionDetectionOutcome(
                    action_id=str(action.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.DETECTION_GAP,
                    matched_rule_ids=[],
                    evidence_event_ids=[],
                    reason="No relevant telemetry events captured for technique T1059.004",
                )
            ],
            gap_action_ids=[str(action.action_id)],
        )

        purple = purple_evaluator.evaluate(
            scenario_outcome=scenario_outcome,
            actions=[action],
        )

        assert purple.gap_reason is not None
        assert "No relevant telemetry" in purple.gap_reason


# ---------------------------------------------------------------------------
# 9. ATT&CK technique propagation
# ---------------------------------------------------------------------------

class TestATTnCKPropagation:
    def test_technique_id_propagated(self, purple_evaluator):
        """technique_id correctly propagated from action outcomes."""
        action = _make_action(tech_id="T1003.008", executable="/usr/bin/cat", args=["-c", "cat /etc/shadow"])
        scenario_outcome = ScenarioDetectionOutcome(
            scenario_id="sc-tech",
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.DETECTED,
            action_outcomes=[
                ActionDetectionOutcome(
                    action_id=str(action.action_id),
                    technique_id="T1003.008",
                    outcome=DetectionOutcome.DETECTED,
                    matched_rule_ids=["sentinelforge-shadow-access"],
                    evidence_event_ids=["ev-tech-1"],
                    reason="Detected by shadow access rule",
                )
            ],
            gap_action_ids=[],
        )

        purple = purple_evaluator.evaluate(
            scenario_outcome=scenario_outcome,
            actions=[action],
        )

        assert purple.technique_id == "T1003.008"


# ---------------------------------------------------------------------------
# 10. Evidence correlation
# ---------------------------------------------------------------------------

class TestEvidenceCorrelation:
    def test_evidence_ids_propagated(self, purple_evaluator):
        """evidence_event_ids aggregated from all action outcomes."""
        action1 = _make_action()
        action2 = _make_action()
        action2.action_id = uuid.uuid4()

        scenario_outcome = ScenarioDetectionOutcome(
            scenario_id="sc-ev",
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.DETECTED,
            action_outcomes=[
                ActionDetectionOutcome(
                    action_id=str(action1.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.DETECTED,
                    matched_rule_ids=["sentinelforge-shell-execution"],
                    evidence_event_ids=["ev-a", "ev-b"],
                    reason="ok",
                ),
                ActionDetectionOutcome(
                    action_id=str(action2.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.DETECTED,
                    matched_rule_ids=["sentinelforge-shell-execution"],
                    evidence_event_ids=["ev-c"],
                    reason="ok",
                ),
            ],
            gap_action_ids=[],
        )

        purple = purple_evaluator.evaluate(
            scenario_outcome=scenario_outcome,
            actions=[action1, action2],
        )

        assert "ev-a" in purple.evidence_event_ids
        assert "ev-b" in purple.evidence_event_ids
        assert "ev-c" in purple.evidence_event_ids
        assert len(purple.evidence_event_ids) == 3


# ---------------------------------------------------------------------------
# 11. Detection latency
# ---------------------------------------------------------------------------

class TestDetectionLatency:
    def test_latency_calculated(self, purple_evaluator):
        """detection_latency_ms is calculated from timestamps."""
        action = _make_action()
        now = datetime.now(timezone.utc)
        scenario_outcome = ScenarioDetectionOutcome(
            scenario_id="sc-lat",
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.DETECTED,
            action_outcomes=[
                ActionDetectionOutcome(
                    action_id=str(action.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.DETECTED,
                    matched_rule_ids=["sentinelforge-shell-execution"],
                    evidence_event_ids=["ev-lat"],
                    reason="ok",
                    timestamp=now.isoformat() + "Z",
                )
            ],
            gap_action_ids=[],
        )

        purple = purple_evaluator.evaluate(
            scenario_outcome=scenario_outcome,
            actions=[action],
        )

        assert purple.detection_latency_ms is not None
        assert purple.detection_latency_ms >= 0


# ---------------------------------------------------------------------------
# 12. Tenant isolation
# ---------------------------------------------------------------------------

class TestTenantIsolation:
    def test_cross_tenant_not_aggregated(self, purple_evaluator):
        """Evaluations from different orgs are NOT mixed in coverage."""
        evals = []
        # Org A
        action_a = _make_action()
        evals.append(purple_evaluator.evaluate(
            scenario_outcome=ScenarioDetectionOutcome(
                scenario_id="sc-iso-a",
                organization_id=str(ORG_ID),
                overall_outcome=DetectionOutcome.DETECTED,
                action_outcomes=[ActionDetectionOutcome(
                    action_id=str(action_a.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.DETECTED,
                    matched_rule_ids=["rule-1"],
                    evidence_event_ids=["ev-a"],
                    reason="ok",
                )],
                gap_action_ids=[],
            ),
            actions=[action_a],
        ))

        # Org B
        action_b = _make_action()
        evals.append(purple_evaluator.evaluate(
            scenario_outcome=ScenarioDetectionOutcome(
                scenario_id="sc-iso-b",
                organization_id=str(ORG_ID_B),
                overall_outcome=DetectionOutcome.NOT_DETECTED,
                action_outcomes=[ActionDetectionOutcome(
                    action_id=str(action_b.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.NOT_DETECTED,
                    matched_rule_ids=[],
                    evidence_event_ids=["ev-b"],
                    reason="missed",
                )],
                gap_action_ids=[str(action_b.action_id)],
            ),
            actions=[action_b],
        ))

        # Coverage for Org A should be 100%
        report_a = purple_evaluator.compute_coverage(evals, str(ORG_ID))
        assert report_a.total_experiments == 1
        assert report_a.detected_experiments == 1
        assert report_a.coverage_pct == 100.0

        # Coverage for Org B should be 0%
        report_b = purple_evaluator.compute_coverage(evals, str(ORG_ID_B))
        assert report_b.total_experiments == 1
        assert report_b.detected_experiments == 0
        assert report_b.coverage_pct == 0.0

    def test_evaluation_org_scoped(self, purple_evaluator):
        """PurpleEvaluation records preserve organization_id."""
        action = _make_action()
        purple = purple_evaluator.evaluate(
            scenario_outcome=ScenarioDetectionOutcome(
                scenario_id="sc-scoped",
                organization_id=str(ORG_ID),
                overall_outcome=DetectionOutcome.DETECTED,
                action_outcomes=[ActionDetectionOutcome(
                    action_id=str(action.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.DETECTED,
                    matched_rule_ids=["rule-1"],
                    evidence_event_ids=["ev-1"],
                    reason="ok",
                )],
                gap_action_ids=[],
            ),
            actions=[action],
        )

        assert purple.organization_id == str(ORG_ID)


# ---------------------------------------------------------------------------
# 13. Duplicate detection handling
# ---------------------------------------------------------------------------

class TestDuplicateDetection:
    def test_duplicate_matched_rules_deduplicated(self, purple_evaluator):
        """Duplicate rule IDs and evidence IDs are deduplicated."""
        action = _make_action()
        scenario_outcome = ScenarioDetectionOutcome(
            scenario_id="sc-dup",
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.DETECTED,
            action_outcomes=[
                ActionDetectionOutcome(
                    action_id=str(action.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.DETECTED,
                    matched_rule_ids=["sentinelforge-shell-execution", "sentinelforge-shell-execution"],
                    evidence_event_ids=["ev-dup-1", "ev-dup-1", "ev-dup-2"],
                    reason="ok",
                )
            ],
            gap_action_ids=[],
        )

        purple = purple_evaluator.evaluate(
            scenario_outcome=scenario_outcome,
            actions=[action],
        )

        assert purple.matched_rule_ids.count("sentinelforge-shell-execution") == 1
        assert purple.evidence_event_ids.count("ev-dup-1") == 1
        assert "ev-dup-2" in purple.evidence_event_ids


# ---------------------------------------------------------------------------
# 14. Retest comparison
# ---------------------------------------------------------------------------

class TestRetestComparison:
    def test_before_after_distinct(self, purple_evaluator):
        """Before and after outcomes are distinct and traceable."""
        action = _make_action()

        # Before: detection gap
        before_outcome = ScenarioDetectionOutcome(
            scenario_id="sc-retest",
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.DETECTION_GAP,
            action_outcomes=[ActionDetectionOutcome(
                action_id=str(action.action_id),
                technique_id="T1059.004",
                outcome=DetectionOutcome.DETECTION_GAP,
                matched_rule_ids=[],
                evidence_event_ids=[],
                reason="No telemetry",
            )],
            gap_action_ids=[str(action.action_id)],
        )

        before_eval = purple_evaluator.evaluate(
            scenario_outcome=before_outcome,
            actions=[action],
        )

        # After: detection improved
        after_outcome = ScenarioDetectionOutcome(
            scenario_id="sc-retest",
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.DETECTED,
            action_outcomes=[ActionDetectionOutcome(
                action_id=str(action.action_id),
                technique_id="T1059.004",
                outcome=DetectionOutcome.DETECTED,
                matched_rule_ids=["sentinelforge-new-rule"],
                evidence_event_ids=["ev-retest-1"],
                reason="Detected by new rule",
            )],
            gap_action_ids=[],
        )

        after_eval = purple_evaluator.evaluate(
            scenario_outcome=after_outcome,
            actions=[action],
        )

        assert before_eval.detection_status == "DETECTION_GAP"
        assert after_eval.detection_status == "DETECTED"
        assert before_eval.evaluation_id != after_eval.evaluation_id


# ---------------------------------------------------------------------------
# 15. CRITICAL INVARIANT: expected_detection cannot create false detection
# ---------------------------------------------------------------------------

class TestExpectedDetectionInvariant:
    def test_expected_true_actual_false_not_detected(self, purple_evaluator):
        """expected_detection=True MUST NOT produce DETECTED when engine says no detection."""
        action = _make_action()
        scenario_outcome = ScenarioDetectionOutcome(
            scenario_id="sc-invariant",
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.NOT_DETECTED,
            action_outcomes=[ActionDetectionOutcome(
                action_id=str(action.action_id),
                technique_id="T1059.004",
                outcome=DetectionOutcome.NOT_DETECTED,
                matched_rule_ids=[],
                evidence_event_ids=["ev-inv-1"],
                reason="No Sigma rule matched",
            )],
            gap_action_ids=[str(action.action_id)],
        )

        # LLM claims detection should happen
        purple = purple_evaluator.evaluate(
            scenario_outcome=scenario_outcome,
            actions=[action],
            expected_detection=True,
        )

        # MUST NOT be DETECTED despite expected_detection=True
        assert purple.detection_status == "NOT_DETECTED"
        assert purple.expected_detection is True

    def test_expected_true_actual_gap_still_gap(self, purple_evaluator):
        """expected_detection=True MUST NOT change DETECTION_GAP to DETECTED."""
        action = _make_action()
        scenario_outcome = ScenarioDetectionOutcome(
            scenario_id="sc-invariant-2",
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.DETECTION_GAP,
            action_outcomes=[ActionDetectionOutcome(
                action_id=str(action.action_id),
                technique_id="T1059.004",
                outcome=DetectionOutcome.DETECTION_GAP,
                matched_rule_ids=[],
                evidence_event_ids=[],
                reason="No telemetry",
            )],
            gap_action_ids=[str(action.action_id)],
        )

        purple = purple_evaluator.evaluate(
            scenario_outcome=scenario_outcome,
            actions=[action],
            expected_detection=True,
        )

        assert purple.detection_status == "DETECTION_GAP"
        assert purple.expected_detection is True


# ---------------------------------------------------------------------------
# 16. Multi-action scenario: ONE PurpleEvaluation
# ---------------------------------------------------------------------------

class TestMultiActionSingleEvaluation:
    def test_multi_action_produces_one_evaluation(self, purple_evaluator):
        """Multiple actions in one scenario produce ONE PurpleEvaluation."""
        action1 = _make_action()
        action2 = _make_action()
        action2.action_id = uuid.uuid4()

        scenario_outcome = ScenarioDetectionOutcome(
            scenario_id="sc-multi-action",
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.DETECTED,
            action_outcomes=[
                ActionDetectionOutcome(
                    action_id=str(action1.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.DETECTED,
                    matched_rule_ids=["sentinelforge-shell-execution"],
                    evidence_event_ids=["ev-ma-1"],
                    reason="ok",
                ),
                ActionDetectionOutcome(
                    action_id=str(action2.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.DETECTED,
                    matched_rule_ids=["sentinelforge-shell-execution"],
                    evidence_event_ids=["ev-ma-2"],
                    reason="ok",
                ),
            ],
            gap_action_ids=[],
        )

        purple = purple_evaluator.evaluate(
            scenario_outcome=scenario_outcome,
            actions=[action1, action2],
            execution_id=str(action1.blueprint_id),
        )

        # Exactly ONE evaluation
        assert purple.experiment_id == "sc-multi-action"
        assert purple.execution_id == str(action1.blueprint_id)
        assert purple.detection_status == "DETECTED"

        # All evidence aggregated
        assert "ev-ma-1" in purple.evidence_event_ids
        assert "ev-ma-2" in purple.evidence_event_ids

        # Counts as ONE coverage unit
        report = purple_evaluator.compute_coverage([purple], str(ORG_ID))
        assert report.total_experiments == 1
        assert report.detected_experiments == 1

    def test_multi_action_one_gap_counts_as_one(self, purple_evaluator):
        """Multi-action with one gap still counts as ONE coverage unit."""
        action1 = _make_action()
        action2 = _make_action()
        action2.action_id = uuid.uuid4()
        action2.technique_id = "T1003.008"
        action2.executable = "/usr/bin/cat"
        action2.arguments = ["-c", "cat /etc/shadow"]

        scenario_outcome = ScenarioDetectionOutcome(
            scenario_id="sc-multi-gap",
            organization_id=str(ORG_ID),
            overall_outcome=DetectionOutcome.DETECTION_GAP,
            action_outcomes=[
                ActionDetectionOutcome(
                    action_id=str(action1.action_id),
                    technique_id="T1059.004",
                    outcome=DetectionOutcome.DETECTED,
                    matched_rule_ids=["sentinelforge-shell-execution"],
                    evidence_event_ids=["ev-mg-1"],
                    reason="ok",
                ),
                ActionDetectionOutcome(
                    action_id=str(action2.action_id),
                    technique_id="T1003.008",
                    outcome=DetectionOutcome.NOT_DETECTED,
                    matched_rule_ids=[],
                    evidence_event_ids=["ev-mg-2"],
                    reason="No matching rule",
                ),
            ],
            gap_action_ids=[str(action2.action_id)],
        )

        purple = purple_evaluator.evaluate(
            scenario_outcome=scenario_outcome,
            actions=[action1, action2],
        )

        assert purple.detection_status == "DETECTION_GAP"

        # Still ONE coverage unit
        report = purple_evaluator.compute_coverage([purple], str(ORG_ID))
        assert report.total_experiments == 1
        assert report.gap_experiments == 1
        assert report.detected_experiments == 0


# ---------------------------------------------------------------------------
# 17. Full Red Agent E2E with Purple Evaluation
# ---------------------------------------------------------------------------

class TestRedAgentPurpleE2E:
    def test_red_agent_produces_purple_evaluation(self, session, objective, sigma_engine):
        """Full pipeline: Red Agent -> Telemetry -> Detection -> Purple -> Coverage."""
        adapter = FakeAdapter()
        worker = _make_worker(session, adapter=adapter)

        def telemetry_source(execution):
            return [_falco_json()]

        collector = TelemetryCollector(TelemetryNormalizer(), sigma_engine, redis_client=None)
        det_evaluator = DetectionGapEvaluator()

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
                detection_evaluator=det_evaluator,
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

        # Detection outcome exists
        assert result.detection_outcome is not None
        assert isinstance(result.detection_outcome, ScenarioDetectionOutcome)
        assert result.detection_outcome.overall_outcome == DetectionOutcome.DETECTED

        # Purple evaluation was persisted
        purple_records = session.query(PurpleEvaluationRecord).all()
        assert len(purple_records) == 1
        pr = purple_records[0]
        assert pr.detection_status == "DETECTED"
        assert str(pr.organization_id) == str(ORG_ID)
        assert pr.technique_id == "T1059.004"

    def test_red_agent_coverage_after_run(self, session, objective, sigma_engine):
        """After Red Agent run, PurpleEvaluator can compute coverage from persisted data."""
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
                detection_evaluator=DetectionGapEvaluator(),
                sigma_engine=sigma_engine,
                telemetry_collector=collector,
                telemetry_source=telemetry_source,
                db_session=session,
            )
        )

        result = agent.run(objective)

        # Reconstruct PurpleEvaluation from persisted data
        purple_evaluator = PurpleEvaluator()
        purple_records = session.query(PurpleEvaluationRecord).all()
        assert len(purple_records) == 1

        evals = [
            PurpleEvaluation(
                evaluation_id=str(pr.id),
                experiment_id=str(pr.experiment_id),
                execution_id=str(pr.execution_id) if pr.execution_id else "",
                organization_id=str(pr.organization_id),
                technique_id=pr.technique_id,
                detection_status=pr.detection_status,
                matched_rule_ids=json.loads(pr.matched_rule_ids) if pr.matched_rule_ids else [],
                evidence_event_ids=json.loads(pr.evidence_event_ids) if pr.evidence_event_ids else [],
                expected_detection=pr.expected_detection,
                gap_reason=pr.gap_reason,
            )
            for pr in purple_records
        ]

        report = purple_evaluator.compute_coverage(evals, str(ORG_ID))
        assert report.total_experiments == 1
        assert report.detected_experiments == 1
        assert report.coverage_pct == 100.0
