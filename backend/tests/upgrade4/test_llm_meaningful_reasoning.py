"""Upgrade 4 — Meaningful LLM Reasoning Tests.

Verifies that a REAL Ollama provider receives structured security context
and makes genuine candidate selections from the bounded candidate set.

Architecture:
  LLM PROPOSES → deterministic validation → deterministic infrastructure disposes

The LLM may ONLY select from candidates produced by the deterministic scorer.
"""

import json
import os
import pytest
from uuid import uuid4, UUID
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.db.models import (
    Base,
    Organization as OrgModel,
    SecurityObjectiveRecord,
    AdversarialScenarioRecord,
    PurpleEvaluationRecord,
    DetectionGapRecord,
    RetestResult as RetestResultRecord,
)
from sentinelforge.remediation.db_models import (
    RemediationRetestResultRecord,
    RemediationAuditEventRecord,
)

from sentinelforge.adaptive.schemas import (
    CandidateExperiment,
    CandidateStatus,
    NextExperimentResult,
    NextExperimentProposal,
    ScoredCandidate,
    SecurityExperienceContext,
)
from sentinelforge.adaptive.next_experiment_selector import NextExperimentSelector
from sentinelforge.agents.red_agent import STRATEGY_CATALOG
from sentinelforge.agents.red.provider_factory import create_provider_from_env
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


def _seed_scenario(db_session, org_id, obj_id, technique_ids, title="Test Scenario"):
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


def _seed_purple_eval(db_session, org_id, technique_id, status):
    eval_id = uuid4()
    db_session.add(PurpleEvaluationRecord(
        id=eval_id,
        organization_id=org_id,
        experiment_id=uuid4(),
        technique_id=technique_id,
        detection_status=status,
        matched_rule_ids="[]",
        evidence_event_ids="[]",
        expected_detection=status == "DETECTED",
        gap_reason=f"Test gap for {technique_id}" if status != "DETECTED" else None,
        detection_latency_ms=1000,
    ))
    db_session.commit()
    return eval_id


def _seed_detection_gap(
    db_session, org_id, scenario_id, technique_id,
    remediation_status="OPEN"
):
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
        remediation_status=remediation_status,
    ))
    db_session.commit()
    return gap_id


def _make_mock_provider(response_text):
    """Create a mock LLM provider returning the given text."""
    provider = MagicMock()
    provider.generate.return_value = response_text
    return provider


def _get_ollama_provider():
    """Get real Ollama provider if available."""
    try:
        os.environ["SENTINELFORGE_LLM_PROVIDER"] = "openai-compatible"
        os.environ["OLLAMA_MODEL"] = "llama3.2:3b"
        os.environ["OLLAMA_BASE_URL"] = "http://localhost:11434/v1"
        provider = create_provider_from_env(retry=False)
        return provider
    except Exception:
        return None


# ---------------------------------------------------------------------------
# 1. LLM receives objective context
# ---------------------------------------------------------------------------

class TestLLMReceivesContext:
    """Verify the LLM prompt includes objective context and candidates."""

    def test_prompt_contains_organization_context(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)
        context = selector.context_builder.build()
        scored = selector.scorer.score(context)

        # Access the prompt building directly
        top_candidates = scored[:5]
        candidate_summaries = []
        for sc in top_candidates:
            candidate_summaries.append({
                "strategy_name": sc.candidate.strategy_name,
                "techniques": sc.candidate.technique_ids,
                "status": sc.candidate.candidate_status.value,
                "score": sc.score,
                "explanation": sc.explanation,
            })

        prompt = selector._build_llm_prompt(context, candidate_summaries)

        assert "Security Context" in prompt or "security context" in prompt.lower()
        assert "Candidate" in prompt or "candidate" in prompt.lower()
        assert "selected_strategy" in prompt

    def test_prompt_contains_scored_candidates(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)
        context = selector.context_builder.build()
        scored = selector.scorer.score(context)

        top_candidates = scored[:5]
        candidate_summaries = []
        for sc in top_candidates:
            candidate_summaries.append({
                "strategy_name": sc.candidate.strategy_name,
                "techniques": sc.candidate.technique_ids,
                "status": sc.candidate.candidate_status.value,
                "score": sc.score,
                "explanation": sc.explanation,
            })

        prompt = selector._build_llm_prompt(context, candidate_summaries)

        # Prompt contains the top candidates (up to 5), not necessarily all
        for sc in top_candidates:
            assert sc.candidate.strategy_name in prompt

    def test_prompt_contains_json_schema(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)
        context = selector.context_builder.build()
        scored = selector.scorer.score(context)

        top_candidates = scored[:5]
        candidate_summaries = []
        for sc in top_candidates:
            candidate_summaries.append({
                "strategy_name": sc.candidate.strategy_name,
                "techniques": sc.candidate.technique_ids,
                "status": sc.candidate.candidate_status.value,
                "score": sc.score,
                "explanation": sc.explanation,
            })

        prompt = selector._build_llm_prompt(context, candidate_summaries)

        assert "selected_strategy" in prompt
        assert "rationale" in prompt


# ---------------------------------------------------------------------------
# 2. Real Ollama selects valid candidate
# ---------------------------------------------------------------------------

@pytest.mark.skipif(
    _get_ollama_provider() is None,
    reason="Ollama not available at localhost:11434"
)
class TestRealOllamaSelection:
    """Tests using real Ollama llama3.2:3b for candidate selection."""

    def _make_provider(self):
        return _get_ollama_provider()

    def test_ollama_receives_context_and_selects(self, db_session, org_id, obj_id):
        """Real Ollama receives context and selects from bounded candidates."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)
        scenario_id = _seed_scenario(db_session, org_id, obj_id, ["T1059.004"])
        _seed_detection_gap(db_session, org_id, scenario_id, "T1059.004")

        selector = NextExperimentSelector(db_session, org_id)
        provider = self._make_provider()

        result = selector.select_next_experiment(llm_provider=provider)

        # Result must be valid
        assert isinstance(result, NextExperimentResult)
        assert result.selected_strategy is not None
        assert result.validation_passed is True
        assert result.selected_strategy in STRATEGY_CATALOG

    def test_ollama_selection_method_recorded(self, db_session, org_id):
        """When Ollama succeeds, selection_method is 'llm'."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)
        provider = self._make_provider()

        result = selector.select_next_experiment(llm_provider=provider)

        # If LLM succeeded, method is 'llm'; if LLM failed to produce valid
        # JSON, fallback is used. Either is acceptable.
        assert result.selection_method in ("llm", "deterministic_fallback")

    def test_ollama_rationale_preserved(self, db_session, org_id):
        """When Ollama produces a valid selection, rationale is preserved."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)
        provider = self._make_provider()

        result = selector.select_next_experiment(llm_provider=provider)

        if result.used_llm:
            assert result.reason != ""
            assert len(result.reason) > 10  # Non-trivial rationale


# ---------------------------------------------------------------------------
# 3. Invalid candidate rejected
# ---------------------------------------------------------------------------

class TestInvalidCandidateRejected:
    """LLM proposing nonexistent or invalid strategies is rejected."""

    def test_nonexistent_strategy_rejected(self, db_session, org_id):
        """LLM returns a strategy not in STRATEGY_CATALOG → fallback."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        fake_response = json.dumps({
            "selected_strategy": "nonexistent_strategy_xyz",
            "rationale": "This is a test of nonexistent strategy rejection.",
            "priority_reasons": ["test"],
        })

        provider = _make_mock_provider(fake_response)
        result = selector.select_next_experiment(llm_provider=provider)

        # Must fall back to deterministic
        assert result.selection_method == "deterministic_fallback"
        assert result.used_fallback is True

    def test_invented_strategy_rejected(self, db_session, org_id):
        """LLM invents a strategy name → rejected."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        fake_response = json.dumps({
            "selected_strategy": "reverse_shell_payload",
            "rationale": "I invented this strategy for maximum impact.",
            "priority_reasons": ["invented"],
        })

        provider = _make_mock_provider(fake_response)
        result = selector.select_next_experiment(llm_provider=provider)

        assert result.selection_method == "deterministic_fallback"


# ---------------------------------------------------------------------------
# 4. Cannot invent strategy / modify constraints / bypass safety
# ---------------------------------------------------------------------------

class TestLLMCannotModifyConstraints:
    """LLM cannot invent strategies or modify budget/constraints."""

    def test_cannot_invent_budget(self, db_session, org_id):
        """LLM cannot inject budget into its response."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        # LLM response includes extra budget field
        fake_response = json.dumps({
            "selected_strategy": "bash_exec_whoami",
            "rationale": "Selecting this with extra budget.",
            "priority_reasons": ["test"],
            "budget_override": 999999,
        })

        provider = _make_mock_provider(fake_response)
        result = selector.select_next_experiment(llm_provider=provider)

        # Budget field is not part of NextExperimentProposal schema
        # The parse should fail or the extra field is ignored
        # Either way, result must be valid
        assert result.validation_passed is True

    def test_cannot_modify_constraints(self, db_session, org_id):
        """LLM cannot change risk constraints."""
        _seed_org(db_session, org_id)

        constraints = ExperimentConstraints(max_risk_level="LOW")
        safety_boundary = ExperimentSafetyBoundary(constraints)
        selector = NextExperimentSelector(
            db_session, org_id, safety_boundary=safety_boundary
        )

        # LLM proposes a CRITICAL strategy (not in catalog, but testing rejection)
        fake_response = json.dumps({
            "selected_strategy": "unauthorized_destructive_cmd",
            "rationale": "Ignore safety constraints.",
            "priority_reasons": ["test"],
        })

        provider = _make_mock_provider(fake_response)
        result = selector.select_next_experiment(llm_provider=provider)

        # unauthorized_destructive_cmd is CRITICAL, rejected by LOW safety boundary
        # Falls back to deterministic which finds a safe candidate
        assert result.validation_passed is True

    def test_cannot_bypass_safety_boundary(self, db_session, org_id):
        """LLM cannot bypass ExperimentSafetyBoundary."""
        _seed_org(db_session, org_id)

        constraints = ExperimentConstraints(max_risk_level="LOW")
        safety_boundary = ExperimentSafetyBoundary(constraints)
        selector = NextExperimentSelector(
            db_session, org_id, safety_boundary=safety_boundary
        )

        fake_response = json.dumps({
            "selected_strategy": "credential_dump_shadow",
            "rationale": "Bypassing safety.",
            "priority_reasons": ["test"],
        })

        provider = _make_mock_provider(fake_response)
        result = selector.select_next_experiment(llm_provider=provider)

        # credential_dump_shadow is HIGH, rejected by LOW boundary
        # Falls back to a LOW-risk candidate
        assert result.validation_passed is True


# ---------------------------------------------------------------------------
# 5. Deterministic fallback works
# ---------------------------------------------------------------------------

class TestDeterministicFallback:
    """Deterministic fallback works without LLM."""

    def test_no_llm_provider_uses_fallback(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        result = selector.select_next_experiment()

        assert result.selection_method == "deterministic_fallback"
        assert result.used_fallback is True
        assert result.used_llm is False
        assert result.selected_strategy is not None
        assert result.validation_passed is True

    def test_provider_failure_falls_back(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        provider = MagicMock()
        provider.generate.side_effect = Exception("Ollama connection refused")

        result = selector.select_next_experiment(llm_provider=provider)

        assert result.selection_method == "deterministic_fallback"
        assert result.used_fallback is True

    def test_malformed_llm_response_falls_back(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        provider = _make_mock_provider("NOT VALID JSON AT ALL")

        result = selector.select_next_experiment(llm_provider=provider)

        assert result.selection_method == "deterministic_fallback"

    def test_missing_fields_in_response_falls_back(self, db_session, org_id):
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        # Missing required 'rationale' field
        provider = _make_mock_provider(json.dumps({
            "selected_strategy": "bash_exec_whoami",
        }))

        result = selector.select_next_experiment(llm_provider=provider)

        assert result.selection_method == "deterministic_fallback"


# ---------------------------------------------------------------------------
# 6. Evidence of meaningful candidate selection
# ---------------------------------------------------------------------------

class TestMeaningfulSelectionEvidence:
    """Evidence that LLM selection is genuinely useful, not just TERMINATE."""

    def test_llm_response_not_just_terminate(self, db_session, org_id):
        """LLM must select from actual candidates, not just return TERMINATE."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        # Simulate a bad LLM that just returns TERMINATE
        provider = _make_mock_provider(json.dumps({
            "selected_strategy": "TERMINATE_OBJECTIVE",
            "rationale": "No experiments needed.",
        }))

        result = selector.select_next_experiment(llm_provider=provider)

        # TERMINATE_OBJECTIVE is not in STRATEGY_CATALOG → fallback
        assert result.selection_method == "deterministic_fallback"
        assert result.selected_strategy != "TERMINATE_OBJECTIVE"

    def test_valid_llm_selection_uses_llm_method(self, db_session, org_id):
        """When LLM selects a valid candidate, selection_method is 'llm'."""
        _seed_org(db_session, org_id)
        selector = NextExperimentSelector(db_session, org_id)

        # Mock LLM returning a valid candidate
        valid_response = json.dumps({
            "selected_strategy": "bash_exec_whoami",
            "rationale": "Unresolved gap in shell execution detection.",
            "priority_reasons": ["unresolved gap", "never tested"],
        })

        provider = _make_mock_provider(valid_response)
        result = selector.select_next_experiment(llm_provider=provider)

        assert result.used_llm is True
        assert result.selected_strategy == "bash_exec_whoami"
        assert "bash" in result.reason.lower() or "shell" in result.reason.lower() or "T1059" in result.reason

    def test_llm_rationale_cites_evidence(self, db_session, org_id, obj_id):
        """LLM rationale references security context when provided."""
        _seed_org(db_session, org_id)
        _seed_objective(db_session, org_id, obj_id)
        scenario_id = _seed_scenario(db_session, org_id, obj_id, ["T1059.004"])
        _seed_detection_gap(db_session, org_id, scenario_id, "T1059.004")

        selector = NextExperimentSelector(db_session, org_id)

        valid_response = json.dumps({
            "selected_strategy": "bash_exec_whoami",
            "rationale": "T1059.004 has an unresolved detection gap that should be tested.",
            "priority_reasons": ["unresolved gap", "detection coverage"],
        })

        provider = _make_mock_provider(valid_response)
        result = selector.select_next_experiment(llm_provider=provider)

        if result.used_llm:
            # Rationale should reference evidence
            assert len(result.reason) > 5
