"""Phase 9 — Immune Cycle Orchestrator tests.

Tests the ImmuneCycleOrchestrator coordinating existing SentinelForge components
into a complete Cyber Immune lifecycle. Reuses all existing components — no
duplication of component implementations.

pytest conftest (backend/tests/conftest.py) provides the test session factory
and sets SENTINELFORGE_SIGNING_KEY for all tests.
"""

import pytest
from uuid import uuid4, UUID
from datetime import datetime, timezone

from sentinelforge.db.models import Base
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sentinelforge.remediation.persistence import SessionFactory

from sentinelforge.immune_cycle_orchestrator import ImmuneCycleOrchestrator
from sentinelforge.domain.state_machine import CyberImmuneStateMachine
from sentinelforge.domain.exceptions import SecurityRejection
from sentinelforge.defensive.proposal import DefensiveProposal, ProposalType
from sentinelforge.defensive.boundary import DefensiveSafetyBoundary
from sentinelforge.defensive.before_after_comparison import BeforeAfterComparison
from sentinelforge.detection.evaluator import DetectionOutcome, PurpleEvaluator
from sentinelforge.immune_memory import ImmuneMemory
from sentinelforge.organization.security_state import OrganizationSecurityState


@pytest.fixture(autouse=True)
def set_test_signing_key(monkeypatch):
    """Ensure SENTINELFORGE_SIGNING_KEY is set for all tests."""
    monkeypatch.setenv("SENTINELFORGE_SIGNING_KEY", "test-signing-key-for-testing-only")


@pytest.fixture
def db_session():
    """Create an in-memory SQLite session for testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)

    # Import all models so Base metadata is populated
    import sentinelforge.db.models  # noqa: F401
    import sentinelforge.remediation.db_models  # noqa: F401

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def test_session_factory(db_session):
    """Return the db_session fixture (aliased for compatibility)."""
    return db_session


@pytest.fixture
def organization_id():
    """Return a test organization UUID."""
    return uuid4()


@pytest.fixture
def objective_id():
    """Return a test objective UUID."""
    return uuid4()


@pytest.fixture
def orchestrator(db_session, organization_id, objective_id):
    """Create an ImmuneCycleOrchestrator instance for testing."""
    return ImmuneCycleOrchestrator(db_session=db_session, organization_id=organization_id, objective_id=objective_id)


@pytest.fixture
def sample_detection_gap(db_session, organization_id):
    """Create a sample detection gap record for testing."""
    from sentinelforge.db.models import DetectionGapRecord

    gap = DetectionGapRecord(
        id=uuid4(),
        organization_id=organization_id,
        technique_id="T1059.005",
        reason="Test detection gap - T1059.005 not detected",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(gap)
    db_session.commit()
    db_session.refresh(gap)
    return gap


@pytest.fixture
def sample_security_objective(db_session, organization_id):
    """Create a sample security objective for testing."""
    from sentinelforge.db.models import SecurityObjectiveRecord

    obj = SecurityObjectiveRecord(
        id=uuid4(),
        organization_id=organization_id,
        title="Test Objective",
        description="Test objective for Phase 9",
        target_category="linux_host",
        default_risk_level="MEDIUM",
        created_at=datetime.now(timezone.utc),
    )
    db_session.add(obj)
    db_session.commit()
    db_session.refresh(obj)
    return obj


@pytest.fixture
def sample_purple_evaluation(db_session, organization_id, sample_detection_gap):
    """Create a sample Purple evaluation for testing."""
    eval_rec = PurpleEvaluationRecord(
        id=uuid4(),
        organization_id=organization_id,
        experiment_id=uuid4(),
        technique_id="T1059.005",
        detection_status="DETECTION_GAP",
        matched_rule_ids=[],
        evidence_event_ids=[],
        expected_detection=False,
        gap_reason="T1059.005 not detected by existing Sigma rules",
        detection_latency_ms=1500,
        evaluated_at=datetime.now(timezone.utc),
    )
    db_session.add(eval_rec)
    db_session.commit()
    db_session.refresh(eval_rec)
    return eval_rec


@pytest.fixture
def sample_defensive_proposal(organization_id, sample_detection_gap):
    """Create a sample defensive proposal for testing."""
    proposal = DefensiveProposal(
        organization_id=organization_id,
        gap_id=sample_detection_gap.id,
        experiment_id=uuid4(),
        technique_id="T1059.005",
        proposal_type=ProposalType.ADD_DETECTION_RULE,
        description="Add detection rule for T1059.005 process creation events",
        rationale="LLM-generated rationale for adding Sigma rule on process creation with T1059.005",
        expected_effect="Sigma rule will match T1059.005 log deletion/creation events",
    )
    return proposal


# ---------------------------------------------------------------------------
# Test: Complete detection/no-gap path
# ---------------------------------------------------------------------------


class TestNoGapPath:
    """Test the no-gap path where detection was already successful."""

    def test_no_gap_path_successful_detection(self, orchestrator, db_session, objective_id):
        """No-gap path: when attack was already detected, terminate cycle safely."""
        result = orchestrator.run_cycle(
            detection_result="DETECTED",
        )

        assert result["final_state"] is not None
        assert result["path"] == "no_gap"
        assert result["detection_result"] == "DETECTED"
        assert result["evidence"]["no_gap"] is True
        # Should NOT have entered GAP_IDENTIFIED state
        assert result["evidence"]["termination_reason"] == "Successful detection — no defensive improvement needed"

    def test_no_gap_path_with_detection_gap_result(self, orchestrator, db_session, objective_id):
        """No-gap path: DETECTION_GAP result should start the gap path."""
        # DETECTION_GAP triggers the gap path, not no-gap
        # This test verifies the detection result routing
        result = orchestrator.run_cycle(detection_result="DETECTION_GAP")
        assert result["path"] != "no_gap"

    def test_no_gap_path_no_gap_flag(self, orchestrator, db_session):
        """No-gap path: verify no_gap flag in evidence."""
        result = orchestrator.run_cycle(detection_result="DETECTED")
        assert result["evidence"]["no_gap"] is True
        assert "GAP_IDENTIFIED" not in str(result.get("evidence", {}))
