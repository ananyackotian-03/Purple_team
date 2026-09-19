"""Upgrade 6 — Deterministic Detection Gap Model.

Derives per-technique detection gap profiles from persisted experiment
history. All computation is deterministic — no LLM involvement.

The model provides:
- Per-technique detection rate, confidence, and attack success rate
- Gap priority scoring based on evidence
- Recency tracking for staleness detection
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from uuid import UUID

from sentinelforge.adaptive.schemas import DetectionGapProfile


# Recent window: experiments within this many days count as "recent"
RECENT_WINDOW_DAYS = 30

# Minimum experiments before detection_rate is considered reliable
MIN_EXPERIMENTS_FOR_CONFIDENCE = 3


class DetectionGapModel:
    """Deterministic per-technique detection gap analyzer.

    Builds DetectionGapProfile instances from persisted PurpleEvaluation
    and DetectionGap records. All values are derived from evidence.
    """

    def __init__(self, db_session: Any, organization_id: UUID):
        self.db_session = db_session
        self.organization_id = organization_id

    def build_gap_profiles(self) -> List[DetectionGapProfile]:
        """Build detection gap profiles for all techniques in this org.

        Returns a list of DetectionGapProfile, one per technique that
        has been tested or has detection gaps.
        """
        from sentinelforge.db.models import (
            PurpleEvaluationRecord,
            DetectionGapRecord,
        )

        # Query all evaluations for this org
        evaluations = (
            self.db_session.query(PurpleEvaluationRecord)
            .filter(PurpleEvaluationRecord.organization_id == self.organization_id)
            .all()
        )

        # Query all detection gaps for this org
        gaps = (
            self.db_session.query(DetectionGapRecord)
            .filter(DetectionGapRecord.organization_id == self.organization_id)
            .all()
        )

        # Aggregate per-technique data
        tech_data: Dict[str, Dict[str, Any]] = {}

        now = datetime.now(timezone.utc)

        for eval_rec in evaluations:
            tech = eval_rec.technique_id
            if not tech:
                continue

            if tech not in tech_data:
                tech_data[tech] = {
                    "experiments": 0,
                    "detected": 0,
                    "missed": 0,
                    "last_tested": None,
                    "recent_count": 0,
                    "gap_count": 0,
                }

            d = tech_data[tech]
            d["experiments"] += 1

            status = eval_rec.detection_status
            if status == "DETECTED":
                d["detected"] += 1
            elif status in ("NOT_DETECTED", "DETECTION_GAP"):
                d["missed"] += 1

            # Track last tested
            ts = eval_rec.evaluated_at
            if ts:
                if isinstance(ts, datetime):
                    ts_aware = ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
                else:
                    ts_aware = now
                if d["last_tested"] is None or ts_aware > d["last_tested"]:
                    d["last_tested"] = ts_aware

                # Track recent experiments
                days_ago = (now - ts_aware).days
                if days_ago <= RECENT_WINDOW_DAYS:
                    d["recent_count"] += 1

        # Count unresolved gaps per technique
        for gap in gaps:
            tech = gap.technique_id
            if not tech:
                continue
            if tech not in tech_data:
                tech_data[tech] = {
                    "experiments": 0,
                    "detected": 0,
                    "missed": 0,
                    "last_tested": None,
                    "recent_count": 0,
                    "gap_count": 0,
                }
            if gap.remediation_status in ("OPEN", "UNRESOLVED"):
                tech_data[tech]["gap_count"] += 1

        # Build profiles
        profiles = []
        for tech, d in tech_data.items():
            experiments = d["experiments"]
            detected = d["detected"]
            missed = d["missed"]

            # Detection rate: fraction of experiments where detection succeeded
            detection_rate = detected / experiments if experiments > 0 else 0.0

            # Detection confidence: how reliable is the detection rate
            # Confidence increases with more experiments
            if experiments >= MIN_EXPERIMENTS_FOR_CONFIDENCE:
                detection_confidence = detection_rate
            elif experiments > 0:
                # Partial confidence for few experiments
                detection_confidence = detection_rate * (experiments / MIN_EXPERIMENTS_FOR_CONFIDENCE)
            else:
                detection_confidence = 0.0

            # Attack success rate: fraction where attack was NOT detected
            # (higher = attack more successful = more dangerous gap)
            attack_success_rate = missed / experiments if experiments > 0 else 0.0

            # Last tested days ago
            last_tested_days_ago = None
            last_tested_str = None
            if d["last_tested"]:
                delta = max(0, (now - d["last_tested"]).days)
                last_tested_days_ago = delta
                last_tested_str = d["last_tested"].isoformat() + "Z"

            # Priority: weighted combination of gap factors
            # Higher = more urgent to test
            priority = self._compute_priority(
                detection_rate=detection_rate,
                attack_success_rate=attack_success_rate,
                experiments=experiments,
                gap_count=d["gap_count"],
                last_tested_days_ago=last_tested_days_ago,
            )

            profiles.append(DetectionGapProfile(
                technique_id=tech,
                experiments_executed=experiments,
                attacks_detected=detected,
                attacks_missed=missed,
                detection_rate=round(detection_rate, 4),
                detection_confidence=round(detection_confidence, 4),
                attack_success_rate=round(attack_success_rate, 4),
                has_unresolved_gap=d["gap_count"] > 0,
                gap_count=d["gap_count"],
                last_tested=last_tested_str,
                last_tested_days_ago=last_tested_days_ago,
                priority=round(priority, 4),
                recent_experiment_count=d["recent_count"],
            ))

        # Sort by priority descending (highest priority first)
        profiles.sort(key=lambda p: p.priority, reverse=True)
        return profiles

    @staticmethod
    def _compute_priority(
        detection_rate: float,
        attack_success_rate: float,
        experiments: int,
        gap_count: int,
        last_tested_days_ago: Optional[int],
    ) -> float:
        """Compute deterministic priority score for a technique gap.

        Priority is higher when:
        - Detection rate is low (poor detection)
        - Attack success rate is high (attacks succeed often)
        - Few experiments have been run (insufficient testing)
        - Unresolved gaps exist
        - Technique hasn't been tested recently (stale)

        Returns a float 0.0-100.0.
        """
        score = 0.0

        # Detection gap component (0-40 points)
        # Low detection = high priority
        detection_gap_score = (1.0 - detection_rate) * 40.0
        score += detection_gap_score

        # Attack success component (0-30 points)
        # High attack success = high priority
        attack_score = attack_success_rate * 30.0
        score += attack_score

        # Insufficient testing component (0-15 points)
        # Fewer experiments = higher priority
        if experiments == 0:
            score += 15.0
        elif experiments < MIN_EXPERIMENTS_FOR_CONFIDENCE:
            score += 15.0 * (1.0 - experiments / MIN_EXPERIMENTS_FOR_CONFIDENCE)

        # Unresolved gap component (0-10 points)
        if gap_count > 0:
            score += min(10.0, gap_count * 5.0)

        # Staleness component (0-5 points)
        # Not tested recently = higher priority
        if last_tested_days_ago is not None:
            if last_tested_days_ago > RECENT_WINDOW_DAYS:
                # Linear increase up to 5 points over 90 days
                staleness = min(5.0, (last_tested_days_ago - RECENT_WINDOW_DAYS) / 18.0)
                score += staleness
        else:
            # Never tested = maximum staleness
            score += 5.0

        return min(100.0, score)
