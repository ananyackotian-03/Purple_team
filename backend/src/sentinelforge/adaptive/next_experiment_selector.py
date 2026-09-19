"""Phase 10 — Next Experiment Selector.

Orchestrates the adaptive next-experiment selection pipeline:

1. Build SecurityExperienceContext from ImmuneMemory + OrganizationSecurityState
2. Score candidates deterministically
3. (Optional) Ask LLM to select from scored candidates
4. Validate selected experiment through ExperimentSafetyBoundary + PolicyEngine
5. Return structured NextExperimentResult

The LLM is untrusted and optional. Deterministic fallback always works.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sentinelforge.adaptive.experiment_scorer import ExperimentScorer
from sentinelforge.adaptive.schemas import (
    CandidateExperiment,
    NextExperimentProposal,
    NextExperimentResult,
    ScoredCandidate,
    SecurityExperienceContext,
)
from sentinelforge.adaptive.security_experience_context import SecurityExperienceContextBuilder
from sentinelforge.agents.red_agent import STRATEGY_CATALOG
from sentinelforge.domain.experiment import (
    AdversarialScenario,
    ExperimentConstraints,
    PolicyDecisionStatus,
    RiskLevel,
)
from sentinelforge.policy.engine import PolicyEngine
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary

logger = logging.getLogger(__name__)

# Risk level mapping
RISK_MAP = {
    "LOW": RiskLevel.LOW,
    "MEDIUM": RiskLevel.MEDIUM,
    "HIGH": RiskLevel.HIGH,
    "CRITICAL": RiskLevel.CRITICAL,
}


class NextExperimentSelector:
    """Adaptive next-experiment selector.

    Integrates security experience context, deterministic scoring,
    optional LLM reasoning, and deterministic safety validation into
    a single selection pipeline.

    The selector is the Phase 10 entry point for the adaptive immune loop.
    """

    def __init__(
        self,
        db_session: Any,
        organization_id: UUID,
        safety_boundary: Optional[ExperimentSafetyBoundary] = None,
    ):
        self.db_session = db_session
        self.organization_id = organization_id
        self.context_builder = SecurityExperienceContextBuilder(db_session, organization_id)
        self.scorer = ExperimentScorer()
        self.safety_boundary = safety_boundary or ExperimentSafetyBoundary()

    def select_next_experiment(
        self,
        *,
        llm_provider: Any = None,
        objective_id: Optional[UUID] = None,
        is_human_approved: bool = False,
        max_candidates_for_llm: int = 5,
    ) -> NextExperimentResult:
        """Select the next experiment based on security experience.

        Pipeline:
        1. Build context
        2. Score candidates
        3. (Optional) LLM selects from top candidates
        4. Validate through safety boundary
        5. Return result

        Args:
            llm_provider: Optional LLM provider. If None or if LLM fails,
                         deterministic fallback is used.
            objective_id: Optional objective ID for experiment creation.
            is_human_approved: Whether human approval has been granted.
            max_candidates_for_llm: Maximum number of top candidates to
                                   present to the LLM.

        Returns:
            NextExperimentResult with selection details.
        """
        # Step 1: Build deterministic context
        context = self.context_builder.build()

        # Step 2: Score candidates
        scored_candidates = self.scorer.score(context)

        if not scored_candidates:
            return NextExperimentResult(
                organization_id=str(self.organization_id),
                selection_method="deterministic_fallback",
                reason="No candidate experiments available",
                used_fallback=True,
                candidates_count=0,
            )

        # Step 3: Attempt LLM selection (if provider available)
        llm_proposal = None
        if llm_provider is not None:
            try:
                llm_proposal = self._try_llm_selection(
                    context=context,
                    scored_candidates=scored_candidates,
                    max_candidates=max_candidates_for_llm,
                    llm_provider=llm_provider,
                )
            except Exception as e:
                logger.warning("LLM selection failed with exception: %s", e)
                llm_proposal = None

        # Step 4: Select the experiment (LLM or deterministic)
        if llm_proposal is not None:
            # LLM made a valid selection — find the matching candidate
            selected = self._resolve_llm_selection(
                llm_proposal, scored_candidates
            )
            if selected is not None:
                # Validate the LLM selection through safety boundary
                validation = self._validate_selection(selected.candidate, is_human_approved)

                if not validation["passed"]:
                    # LLM selection failed validation — fall back to deterministic
                    logger.warning(
                        "LLM selection '%s' failed validation: %s. Falling back.",
                        selected.candidate.strategy_name,
                        validation.get("rejection"),
                    )
                    return self._deterministic_fallback(
                        scored_candidates, is_human_approved
                    )

                return NextExperimentResult(
                    organization_id=str(self.organization_id),
                    selected_strategy=selected.candidate.strategy_name,
                    selected_techniques=selected.candidate.technique_ids,
                    selection_method="llm",
                    score=selected.score,
                    reason=llm_proposal.rationale,
                    validation_passed=True,
                    used_llm=True,
                    used_fallback=False,
                    candidates_count=len(scored_candidates),
                    evidence_references=selected.candidate.related_gap_ids,
                )
            else:
                logger.warning(
                    "LLM selected invalid strategy '%s', falling back to deterministic",
                    llm_proposal.selected_strategy,
                )

        # Step 5: Deterministic fallback — select highest-scoring valid candidate
        return self._deterministic_fallback(
            scored_candidates, is_human_approved
        )

    def _try_llm_selection(
        self,
        context: SecurityExperienceContext,
        scored_candidates: List[ScoredCandidate],
        max_candidates: int,
        llm_provider: Any = None,
    ) -> Optional[NextExperimentProposal]:
        """Attempt to get an LLM selection. Returns None on any failure.

        The LLM receives structured context and scored candidates, and
        must return a structured NextExperimentProposal.
        """
        try:
            if llm_provider is None:
                return None

            # Build the LLM prompt with structured data
            top_candidates = scored_candidates[:max_candidates]
            candidate_summaries = []
            for sc in top_candidates:
                candidate_summaries.append({
                    "strategy_name": sc.candidate.strategy_name,
                    "techniques": sc.candidate.technique_ids,
                    "status": sc.candidate.candidate_status.value,
                    "score": sc.score,
                    "explanation": sc.explanation,
                })

            prompt = self._build_llm_prompt(context, candidate_summaries)

            system_prompt = (
                "You are a security experiment selection assistant. "
                "You MUST select one of the provided candidate strategies. "
                "Respond ONLY with valid JSON matching the required schema."
            )

            # Call the real LLM provider
            response = llm_provider.generate(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.2,
            )

            if response is None:
                return None

            # Parse and validate the structured output
            proposal = self._parse_llm_response(response)
            return proposal

        except Exception as e:
            logger.warning("LLM selection failed: %s", e)
            return None

    def _build_llm_prompt(
        self,
        context: SecurityExperienceContext,
        candidate_summaries: List[Dict[str, Any]],
    ) -> str:
        """Build a structured prompt for the LLM."""
        return (
            "You are a security experiment selection assistant.\n\n"
            "Given the following organization security context and scored "
            "candidate experiments, select the most valuable next experiment.\n\n"
            "## Organization Security Context\n"
            f"- Organization ID: {context.organization_id}\n"
            f"- Total experiments: {context.total_experiments}\n"
            f"- Detection coverage: {context.coverage_pct:.1f}%\n"
            f"- Unresolved gaps: {context.unresolved_gaps}\n"
            f"- Mitigated gaps: {context.mitigated_gaps}\n"
            f"- Techniques tested: {', '.join(context.techniques_tested) or 'none'}\n"
            f"- Techniques with unresolved gaps: {', '.join(context.techniques_with_gap) or 'none'}\n"
            f"- Failed improvements: {context.failed_improvements}\n\n"
            "## Candidate Experiments (sorted by priority score)\n"
            + json.dumps(candidate_summaries, indent=2)
            + "\n\n"
            "Respond with a JSON object:\n"
            '{"selected_strategy": "<strategy_name>", '
            '"rationale": "<why this is the best next experiment>", '
            '"priority_reasons": ["<reason1>", "<reason2>"]}\n'
        )

    def _parse_llm_response(
        self, response: str
    ) -> Optional[NextExperimentProposal]:
        """Parse and validate the LLM response into NextExperimentProposal."""
        try:
            # Try to parse as JSON
            data = json.loads(response)
            proposal = NextExperimentProposal(**data)
            return proposal
        except (json.JSONDecodeError, Exception) as e:
            logger.warning("Failed to parse LLM response: %s", e)
            return None

    def _resolve_llm_selection(
        self,
        proposal: NextExperimentProposal,
        scored_candidates: List[ScoredCandidate],
    ) -> Optional[ScoredCandidate]:
        """Resolve the LLM's selected strategy to a scored candidate."""
        for sc in scored_candidates:
            if sc.candidate.strategy_name == proposal.selected_strategy:
                return sc
        return None

    def _validate_selection(
        self,
        candidate: CandidateExperiment,
        is_human_approved: bool,
    ) -> Dict[str, Any]:
        """Validate the selected candidate through ExperimentSafetyBoundary.

        Creates a minimal AdversarialScenario and evaluates it through
        the deterministic safety boundary.
        """
        try:
            risk_level = RISK_MAP.get(candidate.proposed_risk_level, RiskLevel.MEDIUM)

            scenario = AdversarialScenario(
                objective_id=UUID(int=0),  # placeholder
                organization_id=self.organization_id,
                title=candidate.title,
                strategy_description=candidate.description,
                technique_ids=candidate.technique_ids,
                proposed_risk_level=risk_level,
                created_by="next_experiment_selector",
            )

            decision = self.safety_boundary.evaluate_scenario(
                scenario, is_human_approved=is_human_approved
            )

            if decision.status == PolicyDecisionStatus.ALLOWED:
                return {"passed": True}
            else:
                return {
                    "passed": False,
                    "rejection": decision.reason,
                }

        except Exception as e:
            return {
                "passed": False,
                "rejection": f"Validation error: {e}",
            }

    def _deterministic_fallback(
        self,
        scored_candidates: List[ScoredCandidate],
        is_human_approved: bool,
    ) -> NextExperimentResult:
        """Deterministic fallback selection — highest-scoring valid candidate.

        This always works, even without an LLM.
        """
        for sc in scored_candidates:
            validation = self._validate_selection(sc.candidate, is_human_approved)
            if validation["passed"]:
                return NextExperimentResult(
                    organization_id=str(self.organization_id),
                    selected_strategy=sc.candidate.strategy_name,
                    selected_techniques=sc.candidate.technique_ids,
                    selection_method="deterministic_fallback",
                    score=sc.score,
                    reason=sc.explanation,
                    validation_passed=True,
                    used_llm=False,
                    used_fallback=True,
                    candidates_count=len(scored_candidates),
                    evidence_references=sc.candidate.related_gap_ids,
                )

        # No valid candidate found
        return NextExperimentResult(
            organization_id=str(self.organization_id),
            selection_method="deterministic_fallback",
            reason="No valid candidate passed safety validation",
            validation_passed=False,
            used_llm=False,
            used_fallback=True,
            candidates_count=len(scored_candidates),
        )



