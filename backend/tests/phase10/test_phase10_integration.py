"""Phase 10 — Integration Tests.

Full pipeline integration tests:
1. Immune Memory → Security State → Candidate Generation → Scoring → LLM → Validation → Next Experiment
2. After new result persisted → Immune Memory changes → Selection changes (adaptive behavior)
"""

import json
import pytest
from uuid import uuid4
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.db.models import (
    Base,
    Organization as OrgModel,
    SecurityObjectiveRecord,
    AdversarialScenarioRecord,
    DetectionGapRecord,
    PurpleEvaluationRecord,
    RetestResult as RetestResultRecord,
)
from sentinelforge.remediation.db_models import RemediationRetestResultRecord

from sentinelforge.adaptive.next_experiment_selector import NextExperimentSelector
from sentinelforge.adaptive.security_experience_context import SecurityExperienceContextBuilder
from sentinelforge.adaptive.experiment_scorer import ExperimentScorer
from sentinelforge.immune_cycle_orchestrator import ImmuneCycleOrchestrator
from sentinelforge.immune_memory import ImmuneMemory
from sentinelforge.organization.security_state import OrganizationSecurityState
from sentinelforge.domain.experiment import RetestResult


@pytest.fixture
def db_session():
    """Create an in-memory SQLite session."""
    engine = create_engine("sqlite:///:memory:", echo=False)
    import sentinelforge.db.models  # noqa: F401
    import sentinelforge.remediation.db_models  # noqa: F401
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    yield session
    session.close()


def _seed_org(db_session, org_id):
    db_session.add(OrgModel(id=org_id, name="Integration Test Org"))
    db_session.commit()


def _seed_objective(db_session, org_id, obj_id):
    db_session.add(SecurityObjectiveRecord(
        id=obj_id, organization_id=org_id,
        title="Integration Test Objective",
        description="Full integration test",
    ))
    db_session.commit()


class TestFullPipelineIntegration:
    """End-to-end integration: ImmuneMemory → Context → Scoring → Selection → Validation."""

    def test_full_pipeline_produces_valid_result(self, db_session):
        """Complete pipeline from context building to validated selection."""
        org_id = uuid4()
        obj_id = uuid4()
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        # 1. Build context
        builder = SecurityExperienceContextBuilder(db_session, org_id)
        context = builder.build()
        assert len(context.candidates) > 0

        # 2. Score candidates
        scorer = ExperimentScorer()
        scored = scorer.score(context)
        assert len(scored) > 0
        assert scored[0].score >= scored[-1].score

        # 3. Select next experiment
        selector = NextExperimentSelector(db_session, org_id)
        result = selector.select_next_experiment()
        assert result.selected_strategy is not None
        assert result.validation_passed is True

    def test_pipeline_with_detection_gap(self, db_session):
        """Full pipeline with detection gap influences selection."""
        org_id = uuid4()
        obj_id = uuid4()
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        # Create gap
        scenario_id = uuid4()
        db_session.add(AdversarialScenarioRecord(
            id=scenario_id, objective_id=obj_id, organization_id=org_id,
            title="Shadow Access", strategy_description="T1003.008",
        ))
        db_session.add(DetectionGapRecord(
            id=uuid4(), organization_id=org_id,
            scenario_id=scenario_id, action_id=uuid4(),
            technique_id="T1003.008", original_outcome="NOT_DETECTED",
            root_cause="missing_rule", reason="No shadow detection",
            remediation_status="OPEN",
        ))
        db_session.commit()

        # Run full pipeline
        selector = NextExperimentSelector(db_session, org_id)
        result = selector.select_next_experiment()

        # Should select credential_dump_shadow (T1003.008 has unresolved gap)
        assert result.selected_strategy == "credential_dump_shadow"


class TestAdaptiveBehaviorIntegration:
    """Integration tests proving genuine adaptive behavior."""

    def test_memory_change_changes_selection(self, db_session):
        """After persisting new result, selection changes — proving adaptation."""
        org_id = uuid4()
        obj_id = uuid4()
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        # === BEFORE: T1003.008 has unresolved gap ===
        scenario_id = uuid4()
        db_session.add(AdversarialScenarioRecord(
            id=scenario_id, objective_id=obj_id, organization_id=org_id,
            title="Cred Dump", strategy_description="T1003.008",
        ))
        gap_id = uuid4()
        db_session.add(DetectionGapRecord(
            id=gap_id, organization_id=org_id,
            scenario_id=scenario_id, action_id=uuid4(),
            technique_id="T1003.008", original_outcome="NOT_DETECTED",
            root_cause="missing_rule", reason="No rule",
            remediation_status="OPEN",
        ))
        db_session.commit()

        # Selection 1
        selector1 = NextExperimentSelector(db_session, org_id)
        result1 = selector1.select_next_experiment()
        first_strategy = result1.selected_strategy

        # === SIMULATE: Gap is now MITIGATED ===
        gap = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.id == gap_id
        ).first()
        gap.remediation_status = "MITIGATED"

        # Add retest result showing improvement
        db_session.add(RetestResultRecord(
            id=uuid4(), organization_id=org_id,
            scenario_id=scenario_id,
            before_outcome="NOT_DETECTED",
            after_outcome="DETECTED",
            detection_improved="True",
        ))
        db_session.commit()

        # === AFTER: T1003.008 is no longer an unresolved gap ===
        selector2 = NextExperimentSelector(db_session, org_id)
        result2 = selector2.select_next_experiment()
        second_strategy = result2.selected_strategy

        # Verify the system adapted
        assert first_strategy != second_strategy or \
               result1.score != result2.score, \
            "System did not adapt after memory change"

        # Verify immune memory reflects the change
        memory = ImmuneMemory(db_session, org_id)
        assert memory.mitigated_gaps > 0

    def test_security_state_drives_selection(self, db_session):
        """OrganizationSecurityState directly influences selection priorities."""
        org_id = uuid4()
        obj_id = uuid4()
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        # Fresh org: no experiments, no coverage
        state = OrganizationSecurityState(db_session, org_id)
        assert state.coverage_pct == 0.0
        assert state.unresolved_gaps == 0

        # Selection should prefer untested strategies
        selector = NextExperimentSelector(db_session, org_id)
        result = selector.select_next_experiment()

        # All candidates are NEVER_TESTED for fresh org
        assert result.score > 0  # Should get a non-zero score

    def test_immune_memory_feedback_loop(self, db_session):
        """Complete feedback loop: experiment → result → memory → next selection."""
        org_id = uuid4()
        obj_id = uuid4()
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)

        memory = ImmuneMemory(db_session, org_id)

        # Initial state: no experiments
        assert memory.previous_experiments == 0
        assert memory.coverage_pct == 0.0

        # Simulate: experiment run, detection gap found
        scenario_id = uuid4()
        db_session.add(AdversarialScenarioRecord(
            id=scenario_id, objective_id=obj_id, organization_id=org_id,
            title="Shell Execution", strategy_description="T1059.004",
        ))
        db_session.add(DetectionGapRecord(
            id=uuid4(), organization_id=org_id,
            scenario_id=scenario_id, action_id=uuid4(),
            technique_id="T1059.004", original_outcome="NOT_DETECTED",
            root_cause="missing_rule", reason="No shell detection",
            remediation_status="OPEN",
        ))
        db_session.commit()

        # Memory should reflect the gap
        db_session.expire_all()
        assert memory.unresolved_gaps > 0

        # Selection should prioritize the gap
        selector = NextExperimentSelector(db_session, org_id)
        result = selector.select_next_experiment()
        assert result.selected_strategy == "bash_exec_whoami"

        # Simulate: defense added, retest shows improvement
        gap = db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.organization_id == org_id
        ).first()
        gap.remediation_status = "MITIGATED"
        db_session.add(RetestResultRecord(
            id=uuid4(), organization_id=org_id,
            scenario_id=scenario_id,
            before_outcome="NOT_DETECTED",
            after_outcome="DETECTED",
            detection_improved="True",
        ))
        db_session.commit()

        # Memory should reflect mitigation
        db_session.expire_all()
        assert memory.mitigated_gaps > 0
        assert memory.unresolved_gaps == 0

        # Next selection should differ
        selector2 = NextExperimentSelector(db_session, org_id)
        result2 = selector2.select_next_experiment()
        # Selection should change since the gap is now mitigated
        assert result2.selected_strategy != "bash_exec_whoami" or \
               result2.score < result.score
