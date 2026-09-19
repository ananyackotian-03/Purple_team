"""Upgrade 6 — Deterministic Adaptation Metrics.

Measures how SentinelForge adapts over time based on accumulated
security experience. All computation is deterministic — no LLM involvement.

Metrics:
- Detection coverage: detected / executed
- Detection gap: 1.0 - coverage
- Experiment novelty: how different candidates are from recent experiments
- Learning gain: observed increase in security knowledge
- Repetition rate: fraction of unnecessary duplicate experiments
- Adaptation rate: how often candidate ranking changes
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sentinelforge.adaptive.schemas import (
    AdaptationMetrics,
    DetectionGapProfile,
    ScoredCandidate,
)


# Recent window for staleness detection
RECENT_WINDOW_DAYS = 30


class AdaptationMetricsCalculator:
    """Deterministic calculator for adaptation metrics.

    All values are derived from persisted experiment history.
    No LLM input influences these metrics.
    """

    def __init__(self, db_session: Any, organization_id: UUID):
        self.db_session = db_session
        self.organization_id = organization_id

    def compute_metrics(
        self,
        gap_profiles: List[DetectionGapProfile],
        scored_candidates: List[ScoredCandidate] = None,
        previous_ranking: List[str] = None,
    ) -> AdaptationMetrics:
        """Compute all adaptation metrics from current state.

        Args:
            gap_profiles: Current detection gap profiles.
            scored_candidates: Current scored candidate ranking.
            previous_ranking: Strategy names from previous ranking cycle.

        Returns:
            AdaptationMetrics with all deterministic metrics.
        """
        from sentinelforge.db.models import PurpleEvaluationRecord

        # Query all evaluations
        evaluations = (
            self.db_session.query(PurpleEvaluationRecord)
            .filter(PurpleEvaluationRecord.organization_id == self.organization_id)
            .all()
        )

        total = len(evaluations)
        detected = sum(1 for e in evaluations if e.detection_status == "DETECTED")
        missed = sum(1 for e in evaluations if e.detection_status in ("NOT_DETECTED", "DETECTION_GAP"))

        # Detection coverage
        detection_coverage = detected / total if total > 0 else 0.0
        detection_gap = 1.0 - detection_coverage

        # Experiment novelty: how many candidates are untested or rarely tested
        novelty = self._compute_novelty(gap_profiles, scored_candidates)

        # Learning gain: aggregate from gap profiles
        learning_gain = self._compute_aggregate_learning_gain(gap_profiles)

        # Repetition rate: fraction of recent experiments that were redundant
        repetition_rate = self._compute_repetition_rate(evaluations)

        # Adaptation rate: how much the ranking changed
        adaptation_rate = self._compute_adaptation_rate(
            scored_candidates, previous_ranking
        )

        # Technique counts
        techniques_tested = set()
        techniques_detected = set()
        techniques_with_gap = set()
        for p in gap_profiles:
            techniques_tested.add(p.technique_id)
            if p.detection_rate > 0:
                techniques_detected.add(p.technique_id)
            if p.has_unresolved_gap:
                techniques_with_gap.add(p.technique_id)

        return AdaptationMetrics(
            detection_coverage=round(detection_coverage, 4),
            detection_gap=round(detection_gap, 4),
            experiment_novelty=round(novelty, 4),
            learning_gain=round(learning_gain, 4),
            repetition_rate=round(repetition_rate, 4),
            adaptation_rate=round(adaptation_rate, 4),
            total_experiments=total,
            techniques_with_gap=len(techniques_with_gap),
            techniques_detected=len(techniques_detected),
            techniques_tested=len(techniques_tested),
        )

    @staticmethod
    def _compute_novelty(
        gap_profiles: List[DetectionGapProfile],
        scored_candidates: List[ScoredCandidate] = None,
    ) -> float:
        """Compute experiment novelty: fraction of candidates that are novel.

        Novel = never tested, or not tested in the recent window.
        Returns 0.0-1.0.
        """
        if not scored_candidates:
            return 0.0

        novel_count = 0
        for sc in scored_candidates:
            if sc.candidate.times_tested == 0:
                novel_count += 1
            elif sc.candidate.last_tested_days_ago is not None:
                if sc.candidate.last_tested_days_ago > RECENT_WINDOW_DAYS:
                    novel_count += 1
            else:
                novel_count += 1

        return novel_count / len(scored_candidates) if scored_candidates else 0.0

    @staticmethod
    def _compute_aggregate_learning_gain(
        gap_profiles: List[DetectionGapProfile],
    ) -> float:
        """Compute aggregate learning gain from gap profiles.

        Learning gain is high when:
        - Many techniques have been tested
        - Detection confidence varies (some well-detected, some not)
        - There are active gaps to investigate

        Returns a 0.0+ value (not bounded to 1.0).
        """
        if not gap_profiles:
            return 0.0

        total_gain = 0.0
        for p in gap_profiles:
            # Each technique with data contributes learning gain
            if p.experiments_executed > 0:
                # Gain from testing
                base_gain = min(1.0, p.experiments_executed / 5.0)
                # Gain from confidence change
                confidence_gain = p.detection_confidence
                # Gain from gap discovery
                gap_gain = 0.3 if p.has_unresolved_gap else 0.0
                total_gain += (base_gain + confidence_gain + gap_gain) / 3.0

        # Normalize by number of techniques
        return total_gain / len(gap_profiles) if gap_profiles else 0.0

    @staticmethod
    def _compute_repetition_rate(evaluations: list) -> float:
        """Compute fraction of recent experiments that were redundant.

        A redundant experiment tests the same technique that was already
        well-detected in the recent window.
        Returns 0.0-1.0.
        """
        if not evaluations:
            return 0.0

        now = datetime.now(timezone.utc)
        recent_detections: Dict[str, int] = {}
        recent_total = 0
        redundant = 0

        for eval_rec in evaluations:
            ts = eval_rec.evaluated_at
            if not ts:
                continue
            if isinstance(ts, datetime):
                ts_aware = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
            else:
                continue

            days_ago = (now - ts_aware).days
            if days_ago > RECENT_WINDOW_DAYS:
                continue

            recent_total += 1
            tech = eval_rec.technique_id
            if not tech:
                continue

            if tech not in recent_detections:
                recent_detections[tech] = 0

            if eval_rec.detection_status == "DETECTED":
                recent_detections[tech] += 1
                # If this technique was already detected 2+ times recently,
                # this is a redundant experiment
                if recent_detections[tech] > 2:
                    redundant += 1

        return redundant / recent_total if recent_total > 0 else 0.0

    @staticmethod
    def _compute_adaptation_rate(
        scored_candidates: List[ScoredCandidate] = None,
        previous_ranking: List[str] = None,
    ) -> float:
        """Compute how much the candidate ranking changed.

        Measures the fraction of positions that changed between
        the previous and current ranking.
        Returns 0.0-1.0.
        """
        if not scored_candidates or not previous_ranking:
            return 0.0

        current_ranking = [sc.candidate.strategy_name for sc in scored_candidates]

        # Pad to same length
        max_len = max(len(current_ranking), len(previous_ranking))
        current_padded = current_ranking + [""] * (max_len - len(current_ranking))
        previous_padded = previous_ranking + [""] * (max_len - len(previous_ranking))

        # Count position changes
        changes = sum(1 for c, p in zip(current_padded, previous_padded) if c != p)
        return changes / max_len if max_len > 0 else 0.0
