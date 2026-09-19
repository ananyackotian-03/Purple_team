"""Deterministic Organization Security State.

Derives the security state of a digital organization from persisted evidence
rather than LLM claims. All data is sourced from database records that have
already undergone deterministic validation (Safety Boundary, Policy Engine,
Sigma evaluation, Purple Evaluation, Retest).

This service is read-only with respect to execution. It never modifies
ActionIR, SignedBlueprint, PolicyEngine, ExperimentSafetyBoundary, or any
execution state.
"""

from uuid import UUID
from typing import Dict, List, Optional, Any
from datetime import datetime

from sqlalchemy.orm import Session

from sentinelforge.db.models import (
    Organization as OrgModel,
    SecurityObjectiveRecord,
    AdversarialScenarioRecord,
    ExecutionPlanRecord,
    PolicyDecisionRecord,
    DetectionResult,
    PurpleEvaluationRecord,
    DetectionGapRecord,
    RetestResult,
)
from sentinelforge.domain.experiment import RiskLevel, PolicyDecisionStatus
from sentinelforge.detection.evaluator import (
    PurpleEvaluator,
    DetectionOutcome,
    ScenarioDetectionOutcome,
    ActionDetectionOutcome,
)
from sentinelforge.detection.sigma_engine import DetectionOutcome as SigmaDetectionOutcome


# Branch 2 remediation models — imported lazily to avoid hard
# dependency when Branch 2 tables are not yet created.
_REMEDIATION_AVAILABLE = False
try:
    from sentinelforge.remediation.db_models import (
        RemediationProposalRecord,
        RemediationAttemptRecord,
        RemediationRetestResultRecord,
    )
    _REMEDIATION_AVAILABLE = True
except ImportError:
    pass


class OrganizationSecurityState:
    """Deterministic security state for a digital organization.

    State is derived solely from persisted evidence records. No LLM input
    influences the computed state. All querying is scoped by organization_id
    for tenant isolation.
    """

    def __init__(self, db_session: Session, organization_id: UUID):
        self.db_session = db_session
        self.organization_id = organization_id

    # ------------------------------------------------------------------
    # Low-level record queries (tenant-scoped)
    # ------------------------------------------------------------------

    def _get_objectives(self) -> list:
        return self.db_session.query(SecurityObjectiveRecord).filter(
            SecurityObjectiveRecord.organization_id == self.organization_id
        ).all()

    def _get_scenarios(self) -> list:
        return self.db_session.query(AdversarialScenarioRecord).filter(
            AdversarialScenarioRecord.organization_id == self.organization_id
        ).all()

    def _get_execution_plans(self) -> list:
        return self.db_session.query(ExecutionPlanRecord).filter(
            ExecutionPlanRecord.organization_id == self.organization_id
        ).all()

    def _get_policy_decisions(self) -> list:
        return self.db_session.query(PolicyDecisionRecord).filter(
            PolicyDecisionRecord.organization_id == self.organization_id
        ).all()

    def _get_detection_results(self) -> list:
        return self.db_session.query(DetectionResult).filter(
            DetectionResult.organization_id == self.organization_id
        ).all()

    def _get_purple_evaluations(self) -> list:
        return self.db_session.query(PurpleEvaluationRecord).filter(
            PurpleEvaluationRecord.organization_id == self.organization_id
        ).all()

    def _get_detection_gaps(self) -> list:
        return self.db_session.query(DetectionGapRecord).filter(
            DetectionGapRecord.organization_id == self.organization_id
        ).all()

    def _get_retest_results(self) -> list:
        return self.db_session.query(RetestResult).filter(
            RetestResult.organization_id == self.organization_id
        ).all()

    # ------------------------------------------------------------------
    # Core state computation properties (Branch 1 only)
    # ------------------------------------------------------------------

    @property
    def experiments_performed(self) -> int:
        """Number of adversarial scenarios that have been executed."""
        return len(self._get_scenarios())

    @property
    def techniques_tested(self) -> list[str]:
        """Unique technique IDs across all executed scenarios."""
        techniques: set[str] = set()
        for scenario in self._get_scenarios():
            for tid in scenario.technique_ids:
                techniques.add(tid)
        return sorted(techniques)

    @property
    def detected_experiments(self) -> int:
        """Number of experiments where detection_status was DETECTED."""
        count = 0
        for eval_rec in self._get_purple_evaluations():
            if eval_rec.detection_status == "DETECTED":
                count += 1
        return count

    @property
    def missed_experiments(self) -> int:
        """Number of experiments where detection_status was NOT_DETECTED."""
        count = 0
        for eval_rec in self._get_purple_evaluations():
            if eval_rec.detection_status == "NOT_DETECTED":
                count += 1
        return count

    @property
    def detection_gap_experiments(self) -> int:
        """Number of experiments where detection_status was DETECTION_GAP."""
        count = 0
        for eval_rec in self._get_purple_evaluations():
            if eval_rec.detection_status == "DETECTION_GAP":
                count += 1
        return count

    @property
    def coverage_pct(self) -> float:
        """Detection coverage: detected / total evaluated * 100."""
        total = len(self._get_purple_evaluations())
        if total == 0:
            return 0.0
        return (self.detected_experiments / total) * 100.0

    @property
    def mitigated_gaps(self) -> int:
        """Number of detection gaps successfully mitigated via retest.

        A gap is mitigated when a retest demonstrates that the after-outcome
        improved relative to the before-outcome (e.g. NOT_DETECTED -> DETECTED).
        """
        retests = self._get_retest_results()
        count = 0
        for retest in retests:
            if retest.before_outcome and retest.after_outcome:
                if retest.before_outcome != retest.after_outcome:
                    count += 1
        return count

    @property
    def unresolved_gaps(self) -> int:
        """Number of detection gaps that remain open (not yet mitigated)."""
        gap_evaluations = self.detection_gap_experiments
        retests = self._get_retest_results()
        mitigated_count = 0
        for retest in retests:
            if retest.before_outcome and retest.after_outcome:
                if retest.before_outcome != retest.after_outcome:
                    mitigated_count += 1
        return max(0, gap_evaluations - mitigated_count)

    # ------------------------------------------------------------------
    # Defensive improvement properties (Branch 2, optional)
    # ------------------------------------------------------------------

    @property
    def defensive_improvements_attempted(self) -> int:
        """Number of defensive proposals that have been validated and attempted.

        Only available if Branch 2 remediation tables exist in the database.
        Returns 0 otherwise.
        """
        if not _REMEDIATION_AVAILABLE:
            return 0
        prop_count = self.db_session.query(RemediationProposalRecord).filter(
            RemediationProposalRecord.organization_id == self.organization_id
        ).count()
        attempt_count = self.db_session.query(RemediationAttemptRecord).filter(
            RemediationAttemptRecord.organization_id == self.organization_id
        ).count()
        return max(prop_count, attempt_count)

    @property
    def successful_improvements(self) -> int:
        """Number of defensive improvements that resulted in actual detection gain.

        A defensive improvement is "successful" when the retest comparison
        (before -> after) shows a genuine detection improvement (e.g.
        NOT_DETECTED -> DETECTED for the same technique).
        Only available if Branch 2 remediation tables exist.
        Returns 0 otherwise.
        """
        if not _REMEDIATION_AVAILABLE:
            return 0
        from sentinelforge.remediation.db_models import RemediationRetestResultRecord  # type: ignore
        retests = self.db_session.query(RemediationRetestResultRecord).filter(
            RemediationRetestResultRecord.organization_id == self.organization_id
        ).all()
        count = 0
        for r in retests:
            if r.retest_outcome == "VERIFIED":
                count += 1
        return count

    # ------------------------------------------------------------------
    # Full state aggregation
    # ------------------------------------------------------------------

    def compute_state(self) -> Dict[str, Any]:
        """Return the complete organization security state as a dictionary.

        This is the primary API consumed by the ImmuneCycleOrchestrator
        and the backend APIs.
        """
        base_state = {
            "organization_id": str(self.organization_id),
            "experiments_performed": self.experiments_performed,
            "techniques_tested": self.techniques_tested,
            "detected_experiments": self.detected_experiments,
            "missed_experiments": self.missed_experiments,
            "detection_gap_experiments": self.detection_gap_experiments,
            "mitigated_gaps": self.mitigated_gaps,
            "unresolved_gaps": self.unresolved_gaps,
            "coverage_pct": round(self.coverage_pct, 1),
            "computed_at": datetime.utcnow().isoformat() + "Z",
        }

        if _REMEDIATION_AVAILABLE:
            base_state["defensive_improvements_attempted"] = (
                self.defensive_improvements_attempted
            )
            base_state["successful_improvements"] = self.successful_improvements

        return base_state

    def __repr__(self) -> str:
        return (
            f"OrganizationSecurityState("
            f"org_id={self.organization_id}, "
            f"experiments={self.experiments_performed}, "
            f"coverage={self.coverage_pct:.1f}%)"
        )