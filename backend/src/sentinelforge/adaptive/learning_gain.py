"""Upgrade 6 — Deterministic Learning Gain Calculator.

After each experiment, calculates how much the organization's security
knowledge changed. All computation is deterministic — no LLM involvement.

Learning gain measures:
- Whether a new technique was covered
- Whether detection confidence changed
- Whether a new detection gap was discovered
- Reduction in uncertainty about the organization's posture
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sentinelforge.adaptive.schemas import DetectionGapProfile


class LearningGainResult:
    """Deterministic result of a learning gain calculation."""

    __slots__ = (
        "technique_id",
        "new_coverage",
        "confidence_change",
        "gap_discovered",
        "gap_resolved",
        "novelty",
        "total_gain",
        "breakdown",
    )

    def __init__(
        self,
        technique_id: str,
        new_coverage: bool = False,
        confidence_change: float = 0.0,
        gap_discovered: bool = False,
        gap_resolved: bool = False,
        novelty: float = 0.0,
        total_gain: float = 0.0,
        breakdown: Optional[Dict[str, float]] = None,
    ):
        self.technique_id = technique_id
        self.new_coverage = new_coverage
        self.confidence_change = confidence_change
        self.gap_discovered = gap_discovered
        self.gap_resolved = gap_resolved
        self.novelty = novelty
        self.total_gain = total_gain
        self.breakdown = breakdown or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique_id": self.technique_id,
            "new_coverage": self.new_coverage,
            "confidence_change": self.confidence_change,
            "gap_discovered": self.gap_discovered,
            "gap_resolved": self.gap_resolved,
            "novelty": self.novelty,
            "total_gain": self.total_gain,
            "breakdown": self.breakdown,
        }


class LearningGainCalculator:
    """Deterministic calculator for experiment learning gain.

    Compares pre-experiment and post-experiment state to measure
    how much the organization's security knowledge changed.
    """

    def __init__(self, db_session: Any, organization_id: UUID):
        self.db_session = db_session
        self.organization_id = organization_id

    def compute_gain(
        self,
        technique_id: str,
        detection_status: str,
        pre_profiles: List[DetectionGapProfile],
        post_profiles: List[DetectionGapProfile],
    ) -> LearningGainResult:
        """Compute the learning gain from a single experiment.

        Args:
            technique_id: The MITRE technique that was tested.
            detection_status: The detection outcome (DETECTED, NOT_DETECTED, DETECTION_GAP).
            pre_profiles: Gap profiles before the experiment.
            post_profiles: Gap profiles after the experiment.

        Returns:
            LearningGainResult with deterministic gain calculation.
        """
        # Find pre and post profiles for this technique
        pre_profile = self._find_profile(technique_id, pre_profiles)
        post_profile = self._find_profile(technique_id, post_profiles)

        breakdown = {}

        # 1. New coverage: technique was not tested before
        new_coverage = pre_profile is None or pre_profile.experiments_executed == 0
        if new_coverage:
            breakdown["new_coverage"] = 20.0

        # 2. Confidence change: difference in detection confidence
        pre_conf = pre_profile.detection_confidence if pre_profile else 0.0
        post_conf = post_profile.detection_confidence if post_profile else 0.0
        confidence_change = post_conf - pre_conf
        if abs(confidence_change) > 0.01:
            breakdown["confidence_change"] = confidence_change * 30.0

        # 3. Gap discovered: technique now has unresolved gap
        pre_had_gap = pre_profile.has_unresolved_gap if pre_profile else False
        post_has_gap = post_profile.has_unresolved_gap if post_profile else False
        gap_discovered = post_has_gap and not pre_had_gap
        if gap_discovered:
            breakdown["gap_discovered"] = 25.0

        # 4. Gap resolved: technique no longer has unresolved gap
        gap_resolved = pre_had_gap and not post_has_gap
        if gap_resolved:
            breakdown["gap_resolved"] = 15.0

        # 5. Novelty: first time testing this technique
        novelty = 0.0
        if new_coverage:
            novelty = 1.0
        elif pre_profile and post_profile:
            # Partial novelty based on confidence change magnitude
            novelty = min(1.0, abs(confidence_change) * 2.0)
        breakdown["novelty"] = novelty * 10.0

        total_gain = sum(breakdown.values())

        return LearningGainResult(
            technique_id=technique_id,
            new_coverage=new_coverage,
            confidence_change=confidence_change,
            gap_discovered=gap_discovered,
            gap_resolved=gap_resolved,
            novelty=novelty,
            total_gain=round(total_gain, 4),
            breakdown={k: round(v, 4) for k, v in breakdown.items()},
        )

    @staticmethod
    def _find_profile(
        technique_id: str,
        profiles: List[DetectionGapProfile],
    ) -> Optional[DetectionGapProfile]:
        """Find the gap profile for a specific technique."""
        for p in profiles:
            if p.technique_id == technique_id:
                return p
        return None
