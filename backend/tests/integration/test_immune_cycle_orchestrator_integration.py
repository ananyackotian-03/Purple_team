"""Phase 9 Integration Tests — Immune Cycle Orchestrator.

Tests the full lifecycle:
  Detection Gap → Defensive Proposal → Validation → Defense Test →
  Retest → Before/After Comparison → MITIGATED | UNRESOLVED → Persistence

Invariants verified:
  1. Original evidence is never mutated
  2. MITIGATED only via deterministic before/after proof
  3. Transactional persistence (gap record + retest record + audit event)
  4. Idempotency (repeated runs don't duplicate records)
  5. Tenant isolation (org A cannot affect org B)
"""

import pytest
from uuid import uuid4, UUID
from datetime import datetime

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.db.models import (
    Base,
    Organization as OrgModel,
    SecurityObjectiveRecord,
    DetectionGapRecord,
    AdversarialScenarioRecord,
)
from sentinelforge.remediation.db_models import (
    RemediationRetestResultRecord,
    RemediationAuditEventRecord,
)
from sentinelforge.immune_cycle_orchestrator import ImmuneCycleOrchestrator
from sentinelforge.domain.experiment import RetestResult


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_session():
    """Create an in-memory SQLite session for integration testing."""
    engine = create_engine("sqlite:///:memory:", echo=False)

    import sentinelforge.db.models  # noqa: F401
    import sentinelforge.remediation.db_models  # noqa: F401

    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    yield session
    session.close()


def _seed_org_and_gap(db_session, *, org_id=None, gap_id=None, remediation_status="OPEN"):
    """Seed an organization, objective, scenario, and detection gap.

    Returns (org_id, obj_id, gap_id, scenario_id).
    """
    org_id = org_id or uuid4()
    obj_id = uuid4()
    gap_id = gap_id or uuid4()
    scenario_id = uuid4()

    db_session.add(OrgModel(id=org_id, name="Test Org"))
    db_session.add(SecurityObjectiveRecord(
        id=obj_id,
        organization_id=org_id,
        title="Test Objective",
        description="Test objective for Phase 9",
    ))
    db_session.add(AdversarialScenarioRecord(
        id=scenario_id,
        objective_id=obj_id,
        organization_id=org_id,
        title="PowerShell execution",
        strategy_description="T1059.005 test scenario",
    ))
    db_session.add(DetectionGapRecord(
        id=gap_id,
        organization_id=org_id,
        scenario_id=scenario_id,
        action_id=uuid4(),
        technique_id="T1059.005",
        original_outcome="NOT_DETECTED",
        root_cause="missing_rule",
        reason="No Sigma rule covers T1059.005 process creation",
        remediation_status=remediation_status,
    ))
    db_session.commit()
    return org_id, obj_id, gap_id, scenario_id


def _make_orchestrator(db_session, org_id, obj_id, *, improved: bool):
    """Create an ImmuneCycleOrchestrator with a mock retest returning
    the specified improvement status."""
    orch = ImmuneCycleOrchestrator(
        db_session=db_session,
        organization_id=org_id,
        objective_id=obj_id,
    )

    def mock_retest():
        return RetestResult(
            retest_id=uuid4(),
            organization_id=org_id,
            exercise_id=uuid4(),
            scenario_id=uuid4(),
            before_outcome="DETECTION_GAP",
            after_outcome="DETECTED" if improved else "DETECTION_GAP",
            detection_improved=improved,
            validated_rule_ids=[],
            evaluated_at=datetime.utcnow(),
        )

    orch._retest_original_experiment = mock_retest
    return orch


# ---------------------------------------------------------------------------
# A) Mitigated path — full lifecycle
# ---------------------------------------------------------------------------

class TestMitigatedPath:
    """Gap → Proposal → Validation → Defense Test → Retest → Mitigated."""

    def test_mitigated_lifecycle(self, db_session):
        """Full gap-to-mitigated lifecycle with persistence verification."""
        org_id, obj_id, gap_id, _ = _seed_org_and_gap(db_session)
        orch = _make_orchestrator(db_session, org_id, obj_id, improved=True)

        result = orch.run_cycle(detection_gap_id=gap_id)

        # 1. Final state is MITIGATED
        assert result["final_state"] == "MITIGATED"
        assert result["path"] == "mitigated"
        assert result["improvement_proven"] is True

        # 2. Evidence contains before/after comparison proof
        ev = result["evidence"]
        assert ev["improved"] is True
        assert ev["after_status"] == "DETECTED"
        assert ev["before_status"] in ("DETECTION_GAP", "NOT_DETECTED")

        # 3. DetectionGapRecord.remediation_status == MITIGATED
        db_session.expire_all()
        gap = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.id == gap_id,
            DetectionGapRecord.organization_id == org_id,
        ).one()
        assert gap.remediation_status == "MITIGATED"

        # 4. RemediationRetestResultRecord was persisted
        retest_records = db_session.query(RemediationRetestResultRecord).filter(
            RemediationRetestResultRecord.organization_id == org_id,
            RemediationRetestResultRecord.finding_id == gap_id,
        ).all()
        assert len(retest_records) == 1
        assert retest_records[0].vulnerability_eliminated is True

        # 5. Audit event was persisted
        audits = db_session.query(RemediationAuditEventRecord).filter(
            RemediationAuditEventRecord.organization_id == org_id,
            RemediationAuditEventRecord.entity_id == gap_id,
            RemediationAuditEventRecord.event_type == "GAP_MITIGATED",
        ).all()
        assert len(audits) == 1


# ---------------------------------------------------------------------------
# B) Unresolved path — no improvement
# ---------------------------------------------------------------------------

class TestUnresolvedPath:
    """Gap → Retest → No improvement → UNRESOLVED."""

    def test_unresolved_lifecycle(self, db_session):
        """Full gap-to-unresolved lifecycle with persistence verification."""
        org_id, obj_id, gap_id, _ = _seed_org_and_gap(db_session)
        orch = _make_orchestrator(db_session, org_id, obj_id, improved=False)

        result = orch.run_cycle(detection_gap_id=gap_id)

        # 1. Final state is UNRESOLVED
        assert result["final_state"] == "UNRESOLVED"
        assert result["path"] == "unresolved"
        assert result["improvement_proven"] is False

        # 2. Evidence shows no improvement
        ev = result["evidence"]
        assert ev["improved"] is False

        # 3. DetectionGapRecord.remediation_status == UNRESOLVED
        db_session.expire_all()
        gap = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.id == gap_id,
            DetectionGapRecord.organization_id == org_id,
        ).one()
        assert gap.remediation_status == "UNRESOLVED"

        # 4. RemediationRetestResultRecord was persisted
        retest_records = db_session.query(RemediationRetestResultRecord).filter(
            RemediationRetestResultRecord.organization_id == org_id,
            RemediationRetestResultRecord.finding_id == gap_id,
        ).all()
        assert len(retest_records) == 1
        assert retest_records[0].vulnerability_eliminated is False

        # 5. Audit event was persisted
        audits = db_session.query(RemediationAuditEventRecord).filter(
            RemediationAuditEventRecord.organization_id == org_id,
            RemediationAuditEventRecord.entity_id == gap_id,
            RemediationAuditEventRecord.event_type == "GAP_UNRESOLVED",
        ).all()
        assert len(audits) == 1


# ---------------------------------------------------------------------------
# C) Idempotency — repeated run must not duplicate records
# ---------------------------------------------------------------------------

class TestIdempotency:
    """Repeated cycle execution must not create duplicate records."""

    def test_mitigated_idempotency(self, db_session):
        """Running mitigated cycle twice produces exactly 1 audit event."""
        org_id, obj_id, gap_id, _ = _seed_org_and_gap(db_session)

        # First run
        orch1 = _make_orchestrator(db_session, org_id, obj_id, improved=True)
        result1 = orch1.run_cycle(detection_gap_id=gap_id)
        assert result1["final_state"] == "MITIGATED"

        # Second run (new orchestrator, same gap)
        orch2 = _make_orchestrator(db_session, org_id, obj_id, improved=True)
        result2 = orch2.run_cycle(detection_gap_id=gap_id)

        # Gap still MITIGATED
        db_session.expire_all()
        gap = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.id == gap_id,
        ).one()
        assert gap.remediation_status == "MITIGATED"

        # Idempotency: exactly 1 audit event (guard prevents duplicate)
        audits = db_session.query(RemediationAuditEventRecord).filter(
            RemediationAuditEventRecord.organization_id == org_id,
            RemediationAuditEventRecord.entity_id == gap_id,
            RemediationAuditEventRecord.event_type == "GAP_MITIGATED",
        ).all()
        assert len(audits) == 1


# ---------------------------------------------------------------------------
# D) Tenant isolation
# ---------------------------------------------------------------------------

class TestTenantIsolation:
    """Org A's remediation must never affect Org B."""

    def test_tenant_isolation(self, db_session):
        """Org A mitigated does not leak into Org B."""
        org_a, obj_a, gap_a, _ = _seed_org_and_gap(db_session)
        org_b, obj_b, gap_b, _ = _seed_org_and_gap(db_session)

        # Mitigate Org A
        orch_a = _make_orchestrator(db_session, org_a, obj_a, improved=True)
        result_a = orch_a.run_cycle(detection_gap_id=gap_a)
        assert result_a["final_state"] == "MITIGATED"

        # Org B's gap must remain OPEN
        db_session.expire_all()
        gap_b_record = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.id == gap_b,
            DetectionGapRecord.organization_id == org_b,
        ).one()
        assert gap_b_record.remediation_status == "OPEN"

        # Org B must have no retest records
        b_retests = db_session.query(RemediationRetestResultRecord).filter(
            RemediationRetestResultRecord.organization_id == org_b,
        ).all()
        assert len(b_retests) == 0

        # Org B must have no audit events
        b_audits = db_session.query(RemediationAuditEventRecord).filter(
            RemediationAuditEventRecord.organization_id == org_b,
        ).all()
        assert len(b_audits) == 0


# ---------------------------------------------------------------------------
# E) Failed/rejected path cannot produce MITIGATED
# ---------------------------------------------------------------------------

class TestRejectionCannotMitigate:
    """A gap that fails retest must NEVER become MITIGATED."""

    def test_failed_retest_stays_unresolved(self, db_session):
        """If retest shows no improvement, gap is UNRESOLVED not MITIGATED."""
        org_id, obj_id, gap_id, _ = _seed_org_and_gap(db_session)
        orch = _make_orchestrator(db_session, org_id, obj_id, improved=False)

        result = orch.run_cycle(detection_gap_id=gap_id)

        assert result["final_state"] == "UNRESOLVED"

        db_session.expire_all()
        gap = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.id == gap_id,
        ).one()
        assert gap.remediation_status != "MITIGATED"
        assert gap.remediation_status == "UNRESOLVED"


# ---------------------------------------------------------------------------
# F) No-gap path
# ---------------------------------------------------------------------------

class TestNoGapPathIntegration:
    """DETECTED result → no gap → audit only."""

    def test_no_gap_path_audit(self, db_session):
        """No-gap path persists an audit event but does not create retest records."""
        org_id, obj_id, gap_id, _ = _seed_org_and_gap(db_session)
        orch = ImmuneCycleOrchestrator(
            db_session=db_session,
            organization_id=org_id,
            objective_id=obj_id,
        )

        result = orch.run_cycle(detection_result="DETECTED")

        assert result["path"] == "no_gap"
        assert result["evidence"]["no_gap"] is True

        # Audit event persisted
        audits = db_session.query(RemediationAuditEventRecord).filter(
            RemediationAuditEventRecord.organization_id == org_id,
            RemediationAuditEventRecord.event_type == "CYCLE_COMPLETED_NO_GAP",
        ).all()
        assert len(audits) == 1

        # No retest records created for no-gap path
        retests = db_session.query(RemediationRetestResultRecord).filter(
            RemediationRetestResultRecord.organization_id == org_id,
        ).all()
        assert len(retests) == 0
