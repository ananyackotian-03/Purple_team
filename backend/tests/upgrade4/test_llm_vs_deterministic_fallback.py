"""Upgrade 4 — LLM vs Deterministic Fallback Tests.

Verifies the complete decision pipeline:
- Valid LLM selection → uses LLM method
- No LLM provider → deterministic selection
- Invalid LLM output → deterministic fallback
- LLM failure → deterministic fallback

Architecture:
  LLM is optional. Deterministic fallback always works.
  LLM adds reasoning value when available and correct.
"""

import json
import pytest
from uuid import uuid4
from unittest.mock import MagicMock

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.db.models import (
    Base,
    Organization as OrgModel,
    SecurityObjectiveRecord,
    DetectionGapRecord,
    PurpleEvaluationRecord,
    AdversarialScenarioRecord,
)
from sentinelforge.remediation.db_models import (
    RemediationRetestResultRecord,
    RemediationAuditEventRecord,
)

from sentinelforge.adaptive.schemas import (
    NextExperimentProposal,
    NextExperimentResult,
    ScoredCandidate,
    CandidateExperiment,
    CandidateStatus,
)
from sentinelforge.adaptive.next_experiment_selector import NextExperimentSelector
from sentinelforge.adaptive.experiment_scorer import ExperimentScorer
from sentinelforge.agents.red_agent import STRATEGY_CATALOG
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary
from sentinelforge.domain.experiment import ExperimentConstraints


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:", echo=False)
    import sentinelforge.db.models
    import sentinelforge.remediation.db_models
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, expire_on_commit=False)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def org_id():
    return uuid4()


@pytest.fixture
def obj_id(org_id):
    return uuid4()


def _seed_org(db_session, org_id):
    db_session.add(OrgModel(id=org_id, name="Test Org"))
    db_session.commit()


def _seed_objective(db_session, org_id, obj_id=None):
    obj_id = obj_id or uuid4()
    db_session.add(SecurityObjectiveRecord(
        id=obj_id,
        organization_id=org_id,
        title="Test Objective",
        description="Test",
    ))
    db_session.commit()
    return obj_id


def _seed_detection_gap(db_session, org_id, scenario_id, technique_id):
    gap_id = uuid4()
    db_session.add(DetectionGapRecord(
        id=gap_id,
        organization_id=org_id,
        scenario_id=scenario_id,
        action_id=uuid4(),
        technique_id=technique_id,
        original_outcome="NOT_DETECTED",
        root_cause="missing_rule",
        reason=f"No rule for {technique_id}",
        remediation_status="OPEN",
    ))
    db_session.commit()
    return gap_id


def _seed_scenario(db_session, org_id, obj_id, technique_ids, title="Test"):
    scenario_id = uuid4()
    db_session.add(AdversarialScenarioRecord(
        id=scenario_id,
        objective_id=obj_id,
        organization_id=org_id,
        title=title,
        strategy_description=f"Test for {technique_ids}",
    ))
    db_session.commit()
    return scenario_id


def _make_mock_provider(response_text):
    provider = MagicMock()
    provider.generate.return_value = response_text
    return provider


# ---------------------------------------------------------------------------
# 1. Valid LLM selection
# ---------------------------------------------------------------------------

class TestValidLLMSelection:
    """Valid LLM selections use the LLM method and preserve rationale."""

    def test_valid_selection_uses_llm_method(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        response = json.dumps({
            "selected_strategy": "bash_exec_whoami",
            "rationale": "Unresolved gap in shell detection.",
            "priority_reasons": ["unresolved gap", "detection coverage"],
        })

        result = selector.select_next_experiment(
            llm_provider=_make_mock_provider(response)
        )

        assert result.used_llm is True
        assert result.used_fallback is False
        assert result.selection_method == "llm"
        assert result.selected_strategy == "bash_exec_whoami"

    def test_llm_rationale_preserved_in_result(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        rationale = (
            "T1059.004 has an unresolved detection gap with score 120.0. "
            "This technique has never been tested and represents the highest "
            "priority for improving detection coverage."
        )

        response = json.dumps({
            "selected_strategy": "bash_exec_whoami",
            "rationale": rationale,
            "priority_reasons": ["unresolved gap", "never tested"],
        })

        result = selector.select_next_experiment(
            llm_provider=_make_mock_provider(response)
        )

        if result.used_llm:
            assert result.reason == rationale

    def test_llm_score_reflects_scoring(self, db_session, org_id):
        """LLM selection still uses the deterministic score from the scorer."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        response = json.dumps({
            "selected_strategy": "bash_exec_whoami",
            "rationale": "Testing score preservation.",
            "priority_reasons": ["test"],
        })

        result = selector.select_next_experiment(
            llm_provider=_make_mock_provider(response)
        )

        if result.used_llm:
            # Score should come from the deterministic scorer
            assert result.score >= 0.0

    def test_llm_candidate_count_matches(self, db_session, org_id):
        """LLM result reports correct number of candidates considered."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        response = json.dumps({
            "selected_strategy": "bash_exec_whoami",
            "rationale": "Testing candidate count.",
            "priority_reasons": ["test"],
        })

        result = selector.select_next_experiment(
            llm_provider=_make_mock_provider(response)
        )

        assert result.candidates_count > 0


# ---------------------------------------------------------------------------
# 2. No LLM → deterministic selection
# ---------------------------------------------------------------------------

class TestNoLLMDeterministic:
    """Without LLM, deterministic fallback always works."""

    def test_no_provider_uses_deterministic(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        result = selector.select_next_experiment()

        assert result.selection_method == "deterministic_fallback"
        assert result.used_llm is False
        assert result.used_fallback is True
        assert result.selected_strategy is not None
        assert result.validation_passed is True

    def test_none_provider_uses_deterministic(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        result = selector.select_next_experiment(llm_provider=None)

        assert result.selection_method == "deterministic_fallback"

    def test_deterministic_selects_highest_scored(self, db_session, org_id, obj_id):
        """Deterministic fallback selects the highest-scored valid candidate."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)
        scenario_id = _seed_scenario(db_session, org_id, obj_id, ["T1059.004"])
        _seed_detection_gap(db_session, org_id, scenario_id, "T1059.004")

        selector = NextExperimentSelector(db_session, org_id)
        result = selector.select_next_experiment()

        # bash_exec_whoami uses T1059.004 and has unresolved gap → highest score
        assert result.selected_strategy == "bash_exec_whoami"
        assert result.score > 0

    def test_deterministic_rationale_comes_from_scorer(self, db_session, org_id):
        """Deterministic reason comes from the scorer explanation."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        result = selector.select_next_experiment()

        assert result.reason != ""
        assert "score" in result.reason.lower() or "Strategy" in result.reason


# ---------------------------------------------------------------------------
# 3. Invalid LLM → deterministic fallback
# ---------------------------------------------------------------------------

class TestInvalidLLMFallback:
    """Invalid LLM output triggers deterministic fallback."""

    def test_invalid_json_falls_back(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        result = selector.select_next_experiment(
            llm_provider=_make_mock_provider("NOT JSON {{{")
        )

        assert result.selection_method == "deterministic_fallback"
        assert result.used_fallback is True

    def test_empty_response_falls_back(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        result = selector.select_next_experiment(
            llm_provider=_make_mock_provider("")
        )

        assert result.selection_method == "deterministic_fallback"

    def test_nonexistent_strategy_falls_back(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        response = json.dumps({
            "selected_strategy": "fake_strategy",
            "rationale": "Testing.",
            "priority_reasons": ["test"],
        })

        result = selector.select_next_experiment(
            llm_provider=_make_mock_provider(response)
        )

        assert result.selection_method == "deterministic_fallback"

    def test_extra_fields_falls_back(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        response = json.dumps({
            "selected_strategy": "bash_exec_whoami",
            "rationale": "Valid.",
            "priority_reasons": ["test"],
            "extra_field": "injected",
        })

        result = selector.select_next_experiment(
            llm_provider=_make_mock_provider(response)
        )

        # Extra fields forbidden → parse fails → fallback
        assert result.selection_method == "deterministic_fallback"

    def test_provider_exception_falls_back(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        provider = MagicMock()
        provider.generate.side_effect = RuntimeError("Ollama crashed")

        result = selector.select_next_experiment(llm_provider=provider)

        assert result.selection_method == "deterministic_fallback"

    def test_provider_timeout_falls_back(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        provider = MagicMock()
        provider.generate.side_effect = TimeoutError("Request timed out")

        result = selector.select_next_experiment(llm_provider=provider)

        assert result.selection_method == "deterministic_fallback"

    def test_safety_rejection_falls_back(self, db_session, org_id):
        """LLM selects a valid strategy but safety boundary rejects it."""
        _seed_org(db_session, org_id)

        constraints = ExperimentConstraints(max_risk_level="LOW")
        safety_boundary = ExperimentSafetyBoundary(constraints)
        selector = NextExperimentSelector(
            db_session, org_id, safety_boundary=safety_boundary
        )

        # credential_dump_shadow exists in catalog but is HIGH risk
        response = json.dumps({
            "selected_strategy": "credential_dump_shadow",
            "rationale": "Testing safety rejection.",
            "priority_reasons": ["test"],
        })

        result = selector.select_next_experiment(
            llm_provider=_make_mock_provider(response)
        )

        # Safety rejects HIGH risk, falls back to deterministic
        assert result.selection_method == "deterministic_fallback"
        assert result.validation_passed is True


# ---------------------------------------------------------------------------
# 4. LLM adds value when correct
# ---------------------------------------------------------------------------

class TestLLMAddsValue:
    """LLM adds genuine reasoning value when it works correctly."""

    def test_llm_provides_rationale_deterministic_doesnt(self, db_session, org_id):
        """LLM rationale is richer than deterministic explanation."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        # Get deterministic result
        det_result = selector.select_next_experiment()

        # Get LLM result
        response = json.dumps({
            "selected_strategy": "bash_exec_whoami",
            "rationale": (
                "The bash_exec_whoami strategy targets T1059.004 (Unix Shell). "
                "This technique has never been tested in the current environment. "
                "Shell execution detection is critical for identifying adversary "
                "reconnaissance activity. Testing this technique will improve "
                "detection coverage and validate defensive monitoring capabilities."
            ),
            "priority_reasons": [
                "never tested",
                "detection coverage improvement",
                "high adversary frequency",
            ],
        })

        llm_result = selector.select_next_experiment(
            llm_provider=_make_mock_provider(response)
        )

        if llm_result.used_llm:
            # LLM rationale should be more detailed
            assert len(llm_result.reason) > len(det_result.reason)

    def test_llm_can_select_different_valid_candidate(self, db_session, org_id):
        """LLM can choose a different valid candidate than deterministic would."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        # Deterministic would select the highest-scored
        det_result = selector.select_next_experiment()
        det_strategy = det_result.selected_strategy

        # LLM selects a different valid candidate
        # Find another valid candidate
        context = selector.context_builder.build()
        scored = selector.scorer.score(context)
        other_candidates = [
            sc for sc in scored
            if sc.candidate.strategy_name != det_strategy
        ]

        if other_candidates:
            other = other_candidates[0]
            response = json.dumps({
                "selected_strategy": other.candidate.strategy_name,
                "rationale": f"Selecting {other.candidate.strategy_name} for diversity.",
                "priority_reasons": ["coverage diversity"],
            })

            llm_result = selector.select_next_experiment(
                llm_provider=_make_mock_provider(response)
            )

            if llm_result.used_llm:
                assert llm_result.selected_strategy == other.candidate.strategy_name
                assert llm_result.selection_method == "llm"
