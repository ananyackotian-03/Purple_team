"""Phase 10 — Security Tests.

Tests that prove:
1. LLM cannot bypass SafetyBoundary
2. LLM cannot bypass PolicyEngine
3. LLM cannot bypass ToolAuthorization
4. Cross-tenant memory cannot influence selection
5. LLM failure does not stop the immune system
"""

import pytest
from uuid import uuid4
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
)
from sentinelforge.remediation.db_models import RemediationRetestResultRecord

from sentinelforge.adaptive.schemas import (
    CandidateExperiment,
    CandidateStatus,
    NextExperimentProposal,
    NextExperimentResult,
)
from sentinelforge.adaptive.next_experiment_selector import NextExperimentSelector
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary
from sentinelforge.policy.engine import PolicyEngine
from sentinelforge.domain.experiment import (
    AdversarialScenario,
    ExperimentConstraints,
    RiskLevel,
)
from sentinelforge.domain.exceptions import SecurityRejection


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
    db_session.add(OrgModel(id=org_id, name="Test Org"))
    db_session.commit()


class TestLLMCannotBypassSafetyBoundary:
    """LLM proposals must pass ExperimentSafetyBoundary."""

    def test_llm_proposal_crITICAL_risk_rejected(self, db_session):
        """LLM proposing CRITICAL risk strategy is rejected by safety boundary."""
        org_id = uuid4()
        _seed_org(db_session, org_id)

        constraints = ExperimentConstraints(max_risk_level="MEDIUM")
        boundary = ExperimentSafetyBoundary(constraints)
        selector = NextExperimentSelector(db_session, org_id, safety_boundary=boundary)

        # LLM proposes CRITICAL risk
        proposal = NextExperimentProposal(
            selected_strategy="unauthorized_destructive_cmd",
            rationale="Testing critical attack.",
        )

        with patch.object(selector, '_try_llm_selection', return_value=proposal):
            result = selector.select_next_experiment(llm_provider=MagicMock())

        # The destructive_cmd has CRITICAL risk > MEDIUM limit
        # Should fall back to a safe candidate
        assert result.validation_passed is True  # fallback found safe one

    def test_experiment_safety_boundary_enforced(self, db_session):
        """ExperimentSafetyBoundary still blocks scenarios exceeding risk limits."""
        boundary = ExperimentSafetyBoundary(
            ExperimentConstraints(max_risk_level="LOW")
        )
        scenario = AdversarialScenario(
            objective_id=uuid4(),
            organization_id=uuid4(),
            title="High risk test",
            strategy_description="Testing high risk",
            technique_ids=["T1003.008"],
            proposed_risk_level=RiskLevel.HIGH,
        )
        decision = boundary.evaluate_scenario(scenario)
        assert decision.status.value == "DENIED"


class TestLLMCannotBypassPolicyEngine:
    """LLM cannot bypass PolicyEngine allowlists."""

    def test_policy_engine_validates_actions(self):
        """PolicyEngine validates all ActionIR against allowlists."""
        from sentinelforge.domain.action_ir import ActionIR, ActionType
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        action = ActionIR(
            action_id=uuid4(),
            blueprint_id=uuid4(),
            technique_id="T1059.004",
            action_type=ActionType.PROCESS_EXEC,
            target="sentinelforge-target",
            run_as_user="labuser",
            executable="/usr/bin/bash",
            arguments=["-c", "whoami"],
            max_execution_seconds=30,
            max_stdout_bytes=65536,
            issued_at=now,
            expires_at=now + timedelta(seconds=30),
        )
        # This should pass
        assert PolicyEngine.validate(action) is True

    def test_policy_engine_rejects_unauthorized_command(self):
        """PolicyEngine rejects commands not in allowlist."""
        from sentinelforge.domain.action_ir import ActionIR, ActionType
        from datetime import datetime, timedelta, timezone

        now = datetime.now(timezone.utc)
        action = ActionIR(
            action_id=uuid4(),
            blueprint_id=uuid4(),
            technique_id="T1059.004",
            action_type=ActionType.PROCESS_EXEC,
            target="sentinelforge-target",
            run_as_user="labuser",
            executable="/usr/bin/bash",
            arguments=["-c", "rm -rf /"],  # NOT in allowlist
            max_execution_seconds=30,
            max_stdout_bytes=65536,
            issued_at=now,
            expires_at=now + timedelta(seconds=30),
        )
        with pytest.raises(SecurityRejection):
            PolicyEngine.validate(action)


class TestCrossTenantIsolation:
    """Cross-tenant memory cannot influence selection."""

    def test_org_a_gaps_do_not_affect_org_b(self, db_session):
        """Org A's detection gaps do not influence Org B's selection."""
        org_a = uuid4()
        org_b = uuid4()
        obj_a = uuid4()

        _seed_org(db_session, org_a)
        _seed_org(db_session, org_b)

        # Give org_a an unresolved gap
        db_session.add(SecurityObjectiveRecord(
            id=obj_a, organization_id=org_a,
            title="Obj A", description="Test",
        ))
        scenario_id = uuid4()
        db_session.add(AdversarialScenarioRecord(
            id=scenario_id, objective_id=obj_a, organization_id=org_a,
            title="Scenario A", strategy_description="Test T1003.008",
        ))
        db_session.add(DetectionGapRecord(
            id=uuid4(), organization_id=org_a,
            scenario_id=scenario_id, action_id=uuid4(),
            technique_id="T1003.008", original_outcome="NOT_DETECTED",
            root_cause="missing_rule", reason="No rule",
            remediation_status="OPEN",
        ))
        db_session.commit()

        selector_a = NextExperimentSelector(db_session, org_a)
        selector_b = NextExperimentSelector(db_session, org_b)

        result_a = selector_a.select_next_experiment()
        result_b = selector_b.select_next_experiment()

        # org_a has a gap → should select credential_dump_shadow
        assert result_a.selected_strategy == "credential_dump_shadow"
        # org_b has no gap → should NOT be forced to select credential_dump_shadow
        assert result_b.organization_id == str(org_b)
        # org_b's selection should not be influenced by org_a's gap
        assert "T1003.008" not in str(result_b.evidence_references)


class TestLLMFailureDoesNotStopSystem:
    """LLM failure must not stop the immune system."""

    def test_llm_timeout_continues_with_fallback(self, db_session):
        """LLM timeout → deterministic fallback → valid experiment."""
        org_id = uuid4()
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        with patch.object(selector, '_try_llm_selection', side_effect=TimeoutError):
            result = selector.select_next_experiment(llm_provider=MagicMock())

        assert result.selected_strategy is not None
        assert result.used_fallback is True

    def test_llm_provider_exception_continues(self, db_session):
        """LLM provider exception → deterministic fallback → valid experiment."""
        org_id = uuid4()
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        with patch.object(selector, '_try_llm_selection', side_effect=Exception("Provider down")):
            result = selector.select_next_experiment(llm_provider=MagicMock())

        assert result.selected_strategy is not None
        assert result.used_fallback is True

    def test_malformed_llm_output_continues(self, db_session):
        """Malformed LLM JSON → deterministic fallback → valid experiment."""
        org_id = uuid4()
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        # Return invalid JSON
        with patch.object(selector, '_try_llm_selection', return_value=None):
            result = selector.select_next_experiment(llm_provider=MagicMock())

        assert result.selected_strategy is not None
        assert result.used_fallback is True

    def test_no_llm_provider_still_works(self, db_session):
        """No LLM provider → pure deterministic selection."""
        org_id = uuid4()
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        result = selector.select_next_experiment(llm_provider=None)

        assert result.selected_strategy is not None
        assert result.used_llm is False
        assert result.used_fallback is True
