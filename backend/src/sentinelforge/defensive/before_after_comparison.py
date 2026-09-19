"""Deterministic Before/After Evaluation Comparison.

Compares two PurpleEvaluation records (before and after a defensive
improvement) to determine whether the improvement actually improved
detection outcomes.

The comparison is derived SOLELY from actual evaluation records. The LLM
cannot influence the comparison results except by proposing a defensive
change that is then validated through the retest pipeline.

Never fabricate state. Never trust LLM claims about improvement.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4

from sentinelforge.detection.evaluator import (
    DetectionOutcome,
    PurpleEvaluator,
    CoverageReport,
)


@dataclass(kw_only=True)
class BeforeAfterComparison:
    """Deterministic before/after comparison of detection evaluations.

    This dataclass holds the result of comparing a before-evaluation and
    an after-evaluation to determine if a defensive improvement was
    successful.

    All fields are populated from actual PurpleEvaluation records. The LLM
    cannot set or modify these values directly.
    """

    comparison_id: UUID = field(
        default_factory=uuid4,
        metadata={"description": "Unique comparison identifier"},
    )
    organization_id: UUID = field(
        metadata={"description": "Organization identifier for tenant isolation"},
    )
    comparison_date: str = field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        metadata={"description": "When the comparison was performed"},
    )

    # Before evaluation (the state before defensive improvement)
    before_evaluation_id: str = field(
        metadata={"description": "Persistent PurpleEvaluation record ID for the before state"}
    )
    before_status: DetectionOutcome = field(
        metadata={"description": "Detection status before improvement (DETECTED/NOT_DETECTED/DETECTION_GAP)"}
    )
    before_coverage: float = field(
        metadata={"description": "Detection coverage percentage before improvement"},
    )
    before_technique: str = field(
        metadata={"description": "Primary technique ID from the before evaluation"}
    )
    before_rule_ids: List[str] = field(
        default_factory=list,
        metadata={"description": "Matched rule IDs from the before evaluation"},
    )
    before_evidence_ids: List[str] = field(
        default_factory=list,
        metadata={"description": "Evidence event IDs from the before evaluation"},
    )

    # After evaluation (the state after defensive improvement attempt)
    after_evaluation_id: str = field(
        metadata={"description": "Persistent PurpleEvaluation record ID for the after state"}
    )
    after_status: DetectionOutcome = field(
        metadata={"description": "Detection status after improvement attempt"}
    )
    after_coverage: float = field(
        metadata={"description": "Detection coverage percentage after improvement attempt"}
    )
    after_technique: str = field(
        metadata={"description": "Primary technique ID from the after evaluation"}
    )
    after_rule_ids: List[str] = field(
        default_factory=list,
        metadata={"description": "Matched rule IDs from the after evaluation"},
    )
    after_evidence_ids: List[str] = field(
        default_factory=list,
        metadata={"description": "Evidence event IDs from the after evaluation"},
    )

    # Improvement determination
    improved: bool = field(
        metadata={"description": "True if after_status represents a genuine improvement over before_status (e.g. NOT_DETECTED -> DETECTED)"}
    )
    coverage_delta: float = field(
        metadata={"description": "after_coverage - before_coverage (percentage point change)"}
    )

    # Audit trail
    evaluated_at: str = field(
        default_factory=lambda: datetime.utcnow().isoformat() + "Z",
        metadata={"description": "When the comparison was performed"},
    )
    comparator: str = field(
        default="BeforeAfterComparison",
        metadata={"description": "Identifier of the component that performed the comparison"},
    )

    # === Derived from actual evaluation records (LLM cannot modify) ===

    @staticmethod
    def from_evaluations(
        before_eval: PurpleEvaluation,
        after_eval: PurpleEvaluation,
        organization_id: UUID,
    ) -> BeforeAfterComparison:
        """Create a BeforeAfterComparison from two PurpleEvaluation records.

        The before and after evaluations are derived from actual detection
        results - NOT from LLM claims. The `expected_detection` metadata field
        on PurpleEvaluation is explicitly ignored in the comparison.

        Improvement is determined deterministically:
        - DETECTED is considered "better than" NOT_DETECTED
        - NOT_DETECTED is considered "better than" DETECTION_GAP
        - Same status = not improved
        - DETECTION_GAP -> DETECTED = improved
        - NOT_DETECTED -> DETECTED = improved
        - Any other transition = not improved
        """
        from sentinelforge.detection.evaluator import DetectionOutcome

        # Parse before status
        before_status_str = before_eval.detection_status
        before_status = DetectionOutcome(before_status_str)

        # Parse after status
        after_status_str = after_eval.detection_status
        after_status = DetectionOutcome(after_status_str)

        # Determine if there was an improvement
        # The ordering: DETECTED > DETECTION_GAP > NOT_DETECTED
        # Improvement means the after status is "higher" than the before status
        status_order = {
            DetectionOutcome.DETECTED: 3,
            DetectionOutcome.DETECTION_GAP: 2,
            DetectionOutcome.NOT_DETECTED: 1,
        }

        before_order = status_order.get(before_status, 0)
        after_order = status_order.get(after_status, 0)

        improved = after_order > before_order

        # Calculate coverage delta
        # Coverage is computed from the PurpleEvaluator's compute_coverage method
        # We derive it from the evaluation records' organization-scoped context
        before_coverage = BeforeAfterCoverage(
            evaluations=[before_eval],
            organization_id=organization_id,
        ).coverage_pct

        after_coverage = BeforeAfterCoverage(
            evaluations=[after_eval],
            organization_id=organization_id,
        ).coverage_pct

        coverage_delta = round(after_coverage - before_coverage, 1)

        # Primary technique from each evaluation
        before_technique = before_eval.technique_id or "unknown"
        after_technique = after_eval.technique_id or "unknown"

        # Matched rule IDs
        before_rule_ids = before_eval.matched_rule_ids or []
        after_rule_ids = after_eval.matched_rule_ids or []

        # Evidence event IDs
        before_evidence_ids = before_eval.evidence_event_ids or []
        after_evidence_ids = after_eval.evidence_event_ids or []

        return BeforeAfterComparison(
            # Comparison identity
            comparison_id=uuid4(),
            organization_id=organization_id,
            comparison_date=datetime.utcnow().isoformat() + "Z",

            # Before evaluation
            before_evaluation_id=before_eval.evaluation_id,
            before_status=before_status,
            before_coverage=before_coverage,
            before_technique=before_technique,
            before_rule_ids=before_rule_ids,
            before_evidence_ids=before_evidence_ids,

            # After evaluation
            after_evaluation_id=after_eval.evaluation_id,
            after_status=after_status,
            after_coverage=after_coverage,
            after_technique=after_technique,
            after_rule_ids=after_rule_ids,
            after_evidence_ids=after_evidence_ids,

            # Improvement determination
            improved=improved,
            coverage_delta=coverage_delta,

            # Audit trail
            evaluated_at=datetime.utcnow().isoformat() + "Z",
            comparator="BeforeAfterComparison",
        )

    def __repr__(self) -> str:
        return (
            f"BeforeAfterComparison("
            f"improved={self.improved}, "
            f"coverage_delta={self.coverage_delta:.1f}%, "
            f"before={self.before_status.value}, "
            f"after={self.after_status.value}, "
            f"org={self.organization_id})"
        )


@dataclass
class BeforeAfterCoverage:
    """Helper to compute coverage for a single evaluation within an organization.

    This is a minimal coverage computation used by BeforeAfterComparison
    to derive before_coverage and after_coverage from individual
    PurpleEvaluation records.
    """

    evaluations: List[PurpleEvaluation]
    organization_id: UUID

    @property
    def coverage_pct(self) -> float:
        """Compute coverage percentage for these evaluations within the organization."""
        total = len(self.evaluations)
        if total == 0:
            return 0.0
        detected = sum(
            1
            for e in self.evaluations
            if e.detection_status == DetectionOutcome.DETECTED.value
        )
        return (detected / total) * 100.0

    @property
    def technique_coverage(self) -> Dict[str, bool]:
        """Per-technique coverage: True if any evaluation for that technique is DETECTED."""
        tech_coverage: Dict[str, bool] = {}
        for e in self.evaluations:
            tech = e.technique_id
            if tech not in tech_coverage:
                tech_coverage[tech] = False
            if e.detection_status == DetectionOutcome.DETECTED.value:
                tech_coverage[tech] = True
        return tech_coverage
