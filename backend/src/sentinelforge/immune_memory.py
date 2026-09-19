"""Persistent Immune Memory.

Reuses existing experiment/evaluation/gap/retest records rather than
duplicating all data. Provides tenant-isolated querying of the immune
lifecycle state.

Every record remains tenant-isolated and evidence-linked via organization_id.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import UUID

from sqlalchemy.orm import Session

from sentinelforge.db.models import (
    Organization as OrgModel,
    DetectionGapRecord,
    PurpleEvaluationRecord,
    RetestResult,
    DetectionResult,
    SecurityObjectiveRecord,
    AdversarialScenarioRecord,
    PolicyDecisionRecord,
)


class ImmuneMemory:
    """Persistent immune memory for a digital organization.

    Queries existing database records to provide a deterministic view of
    the organization's defensive posture, detection history, and improvement
    lifecycle. No LLM input influences the computed values.
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
    # Core immune memory properties
    # ------------------------------------------------------------------

    @property
    def previous_experiments(self) -> int:
        """Number of adversarial scenarios that have been executed."""
        return len(self._get_scenarios())

    @property
    def techniques_tested(self) -> list[str]:
        """Unique technique IDs across all purple evaluations."""
        techniques: set[str] = set()
        for eval_rec in self._get_purple_evaluations():
            if eval_rec.technique_id:
                techniques.add(eval_rec.technique_id)
        return sorted(techniques)

    @property
    def detection_outcomes(self) -> Dict[str, int]:
        """Counts of each detection outcome across all purple evaluations."""
        outcomes: Dict[str, int] = {}
        for eval_rec in self._get_purple_evaluations():
            status = eval_rec.detection_status
            outcomes[status] = outcomes.get(status, 0) + 1
        return outcomes

    @property
    def detection_gaps(self) -> list:
        """List of detection gap records for this organization."""
        return self._get_detection_gaps()

    @property
    def retest_results(self) -> list:
        """List of retest results for this organization."""
        return self._get_retest_results()

    @property
    def unresolved_gaps(self) -> int:
        """Number of detection gaps that remain open (not yet mitigated)."""
        gap_evaluations = len(self._get_detection_gaps())
        retests = self._get_retest_results()
        mitigated_count = 0
        for retest in retests:
            if retest.before_outcome and retest.after_outcome:
                if retest.before_outcome != retest.after_outcome:
                    mitigated_count += 1
        return max(0, gap_evaluations - mitigated_count)

    @property
    def mitigated_gaps(self) -> int:
        """Number of detection gaps successfully mitigated via retest."""
        retests = self._get_retest_results()
        count = 0
        for retest in retests:
            if retest.before_outcome and retest.after_outcome:
                if retest.before_outcome != retest.after_outcome:
                    count += 1
        return count

    @property
    def coverage_pct(self) -> float:
        """Detection coverage: detected / total evaluated * 100."""
        total = len(self._get_purple_evaluations())
        if total == 0:
            return 0.0
        detected = sum(
            1
            for eval_rec in self._get_purple_evaluations()
            if eval_rec.detection_status == "DETECTED"
        )
        return (detected / total) * 100.0

    # ------------------------------------------------------------------
    # Defensive proposal memory
    # ------------------------------------------------------------------

    def get_proposals(self, status: Optional[str] = None) -> list:
        """Get defensive proposals for this organization.

        Returns list of dicts with proposal data from the remediation
        proposal table, or empty list if none found.
        """
        from sentinelforge.remediation.db_models import RemediationProposalRecord

        props = self.db_session.query(RemediationProposalRecord).filter(
            RemediationProposalRecord.organization_id == self.organization_id
        ).all()

        if not props:
            return []

        result = []
        for prop in props:
            result.append({
                'proposal_id': str(prop.id),
                'organization_id': str(prop.organization_id),
                'gap_id': str(prop.finding_id) if prop.finding_id else None,
                'experiment_id': str(prop.scenario_id) if prop.scenario_id else None,
                'technique_id': prop.attack_technique_id if hasattr(prop, 'attack_technique_id') else None,
                'proposal_type': prop.root_cause if hasattr(prop, 'root_cause') else 'OTHER_ALLOWED_DEFENSIVE_CHANGE',
                'description': prop.proposed_remediation if hasattr(prop, 'proposed_remediation') else 'Remediation proposal',
                'rationale': prop.root_cause if hasattr(prop, 'root_cause') else 'Root cause remediation',
                'expected_effect': prop.expected_security_effect if hasattr(prop, 'expected_security_effect') else 'Security improvement',
                'validation_requirements': prop.test_plan if hasattr(prop, 'test_plan') else [],
                'status': prop.status if hasattr(prop, 'status') else 'PROPOSED',
                'created_at': prop.created_at.isoformat() if prop.created_at else datetime.utcnow().isoformat(),
            })
        return result

    def get_successful_improvements(self) -> int:
        """Number of defensive improvements that resulted in actual detection gain."""
        try:
            from sentinelforge.remediation.db_models import RemediationRetestResultRecord

            retests = self.db_session.query(RemediationRetestResultRecord).filter(
                RemediationRetestResultRecord.organization_id == self.organization_id
            ).all()
            count = 0
            for r in retests:
                if r.retest_outcome == "VERIFIED":
                    count += 1
            return count
        except Exception:
            return 0

    def get_failed_improvements(self) -> int:
        """Number of defensive improvements that did not result in detection gain."""
        try:
            from sentinelforge.remediation.db_models import RemediationRetestResultRecord

            retests = self.db_session.query(RemediationRetestResultRecord).filter(
                RemediationRetestResultRecord.organization_id == self.organization_id
            ).all()
            total = len(retests)
            successful = sum(1 for r in retests if r.retest_outcome == "VERIFIED")
            return max(0, total - successful)
        except Exception:
            return 0

    # ------------------------------------------------------------------
    # Full state aggregation
    # ------------------------------------------------------------------

    def compute_state(self) -> Dict[str, Any]:
        """Return the complete immune memory state as a dictionary."""
        from sentinelforge.organization.security_state import OrganizationSecurityState

        ss = OrganizationSecurityState(self.db_session, self.organization_id)

        base_state = {
            "organization_id": str(self.organization_id),
            "previous_experiments": self.previous_experiments,
            "techniques_tested": self.techniques_tested,
            "detection_outcomes": self.detection_outcomes,
            "detection_gaps": [self._summarize_gap(g) for g in self._get_detection_gaps()],
            "retest_results": [self._summarize_retest(r) for r in self._get_retest_results()],
            "coverage_pct": round(ss.coverage_pct, 1),
            "mitigated_gaps": ss.mitigated_gaps,
            "unresolved_gaps": ss.unresolved_gaps,
            "successful_improvements": self.get_successful_improvements(),
            "failed_improvements": self.get_failed_improvements(),
        }

        # Add defensive proposal info
        proposals = self.get_proposals()
        if proposals:
            base_state["defensive_proposals"] = proposals

        return base_state

    @staticmethod
    def _summarize_gap(gap: DetectionGapRecord) -> Dict[str, Any]:
        """Summarize a detection gap record."""
        return {
            "id": str(gap.id),
            "technique_id": gap.technique_id,
            "reason": gap.reason,
            "remediation_status": gap.remediation_status,
            "created_at": gap.created_at.isoformat() if gap.created_at else None,
        }

    @staticmethod
    def _summarize_retest(retest: RetestResult) -> Dict[str, Any]:
        """Summarize a retest result."""
        return {
            "id": str(retest.id),
            "before_outcome": retest.before_outcome,
            "after_outcome": retest.after_outcome,
            "detection_improved": retest.detection_improved,
            "evaluated_at": retest.evaluated_at.isoformat() if retest.evaluated_at else None,
        }

    def __repr__(self) -> str:
        return (
            "ImmuneMemory("
            f"org_id={self.organization_id}, "
            f"experiments={self.previous_experiments}, "
            f"coverage={self.coverage_pct:.1f}%)"
        )
