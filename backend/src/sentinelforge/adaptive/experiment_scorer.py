"""Phase 10 + Upgrade 6 — Deterministic Experiment Scorer.

Transparent, explainable scoring mechanism that ranks candidate experiments
based on the security experience context. No machine learning — a simple
weighted scoring model that is auditable and explainable.

Scoring priorities:
1. Unresolved detection gaps (highest priority)
2. High-value techniques not yet tested
3. Techniques with previously failed defenses
4. Areas with weak detection coverage
5. Techniques not tested recently
6. Upgrade 6: Detection gap magnitude
7. Upgrade 6: Attack success history
8. Upgrade 6: Experiment novelty
9. Upgrade 6: Learning value

Deprioritized:
- Repeatedly successful experiments
- Redundant duplicate experiments
- Techniques already thoroughly validated
- Upgrade 6: Recently tested techniques
"""

from __future__ import annotations

from typing import List

from sentinelforge.adaptive.schemas import (
    CandidateExperiment,
    CandidateStatus,
    ScoredCandidate,
    SecurityExperienceContext,
)

# Scoring weights — transparent and explainable
# Higher weight = higher priority for selection
WEIGHTS = {
    "unresolved_gap": 100.0,
    "defense_failed": 80.0,
    "never_tested": 60.0,
    "not_detected": 50.0,
    "weak_coverage": 30.0,
    "recently_gap": 20.0,
    "deprioritize_detected": -40.0,
    "deprioritize_redundant": -30.0,
    # Upgrade 6 — Adaptive weights
    "detection_gap_magnitude": 35.0,
    "attack_success_history": 25.0,
    "novelty_boost": 15.0,
    "learning_value": 20.0,
    "deprioritize_recently_tested": -20.0,
    "deprioritize_stale_confidence": -10.0,
}


class ExperimentScorer:
    """Deterministic scorer for candidate experiments.

    Computes a transparent priority score for each candidate based on
    the security experience context. The score is fully explainable —
    every component is recorded in score_breakdown.
    """

    def score(
        self,
        context: SecurityExperienceContext,
        candidates: List[CandidateExperiment] = None,
    ) -> List[ScoredCandidate]:
        """Score all candidates (or a provided subset) and return sorted results.

        Args:
            context: The deterministic security experience context.
            candidates: Optional subset of candidates to score. If None,
                       all candidates from context are scored.

        Returns:
            List of ScoredCandidate sorted by score descending.
        """
        if candidates is None:
            candidates = context.candidates

        scored = []
        for candidate in candidates:
            sc = self._score_candidate(context, candidate)
            scored.append(sc)

        # Sort by score descending (highest priority first)
        scored.sort(key=lambda x: x.score, reverse=True)
        return scored

    def _score_candidate(
        self,
        context: SecurityExperienceContext,
        candidate: CandidateExperiment,
    ) -> ScoredCandidate:
        """Compute the deterministic score for a single candidate.

        Upgrade 6 adds adaptive scoring components based on evidence.
        """
        breakdown = {}
        total = 0.0

        # --- Priority 1: Unresolved detection gaps ---
        if candidate.has_unresolved_gap:
            w = WEIGHTS["unresolved_gap"]
            breakdown["unresolved_gap"] = w
            total += w

        # --- Priority 2: Previously failed defense ---
        if candidate.defense_failed:
            w = WEIGHTS["defense_failed"]
            breakdown["defense_failed"] = w
            total += w

        # --- Priority 3: Never tested ---
        if candidate.candidate_status == CandidateStatus.NEVER_TESTED:
            w = WEIGHTS["never_tested"]
            breakdown["never_tested"] = w
            total += w

        # --- Priority 4: Previously not detected ---
        if candidate.candidate_status == CandidateStatus.NOT_DETECTED:
            w = WEIGHTS["not_detected"]
            breakdown["not_detected"] = w
            total += w

        # --- Priority 5: Weak detection coverage ---
        if context.coverage_pct < 50.0 and candidate.times_tested == 0:
            w = WEIGHTS["weak_coverage"]
            breakdown["weak_coverage"] = w
            total += w

        # --- Priority 6: Related to recent gaps ---
        if candidate.candidate_status == CandidateStatus.UNRESOLVED_GAP:
            w = WEIGHTS["recently_gap"]
            breakdown["gap_recency_boost"] = w
            total += w

        # --- Upgrade 6: Detection gap magnitude ---
        # Low detection confidence = high priority
        if candidate.detection_confidence < 0.5 and candidate.times_tested > 0:
            gap_weight = WEIGHTS["detection_gap_magnitude"] * (1.0 - candidate.detection_confidence)
            breakdown["detection_gap_magnitude"] = round(gap_weight, 2)
            total += gap_weight

        # --- Upgrade 6: Attack success history ---
        # High attack success rate = high priority
        if candidate.attack_success_rate > 0.5 and candidate.times_tested > 0:
            attack_weight = WEIGHTS["attack_success_history"] * candidate.attack_success_rate
            breakdown["attack_success_history"] = round(attack_weight, 2)
            total += attack_weight

        # --- Upgrade 6: Novelty boost ---
        # Never tested or not tested recently = exploration value
        novelty = self._compute_novelty_score(candidate)
        if novelty > 0.5:
            novelty_weight = WEIGHTS["novelty_boost"] * novelty
            breakdown["novelty_boost"] = round(novelty_weight, 2)
            total += novelty_weight

        # --- Upgrade 6: Learning value ---
        # Expected learning gain from this experiment
        learning_val = self._compute_learning_value(context, candidate)
        learning_weight = WEIGHTS["learning_value"] * learning_val
        breakdown["learning_value"] = round(learning_weight, 2)
        total += learning_weight

        # --- Deprioritize: Already detected / successful ---
        if candidate.candidate_status == CandidateStatus.RECENTLY_DETECTED:
            w = WEIGHTS["deprioritize_detected"]
            breakdown["deprioritize_detected"] = w
            total += w

        # --- Deprioritize: Redundant (tested many times with same result) ---
        if candidate.times_tested > 2 and candidate.times_detected > 0:
            w = WEIGHTS["deprioritize_redundant"]
            breakdown["deprioritize_redundant"] = w
            total += w

        # --- Upgrade 6: Deprioritize recently tested ---
        if candidate.last_tested_days_ago is not None and candidate.last_tested_days_ago <= 7:
            w = WEIGHTS["deprioritize_recently_tested"]
            breakdown["deprioritize_recently_tested"] = w
            total += w

        # --- Upgrade 6: Deprioritize stale confidence ---
        # If we have high confidence and low attack success, less learning value
        if (candidate.detection_confidence > 0.8
                and candidate.attack_success_rate < 0.2
                and candidate.times_tested >= 3):
            w = WEIGHTS["deprioritize_stale_confidence"]
            breakdown["deprioritize_stale_confidence"] = w
            total += w

        explanation = self._build_explanation(context, candidate, breakdown, total)

        return ScoredCandidate(
            candidate=candidate,
            score=max(0.0, total),
            score_breakdown=breakdown,
            explanation=explanation,
            learning_value=round(learning_val, 4),
        )

    @staticmethod
    def _compute_novelty_score(candidate: CandidateExperiment) -> float:
        """Compute novelty score for a candidate (0.0-1.0).

        Novelty is high when:
        - Technique has never been tested
        - Technique was tested a long time ago
        - Technique was tested recently but few times
        """
        if candidate.times_tested == 0:
            return 1.0

        if candidate.last_tested_days_ago is not None:
            # Recency decay: more recent = less novel
            if candidate.last_tested_days_ago <= 7:
                return 0.1
            elif candidate.last_tested_days_ago <= 30:
                return 0.3
            elif candidate.last_tested_days_ago <= 90:
                return 0.6
            else:
                return 0.8

        # Unknown recency — moderate novelty based on test count
        return max(0.0, 1.0 - candidate.times_tested * 0.2)

    @staticmethod
    def _compute_learning_value(
        context: SecurityExperienceContext,
        candidate: CandidateExperiment,
    ) -> float:
        """Compute expected learning value for a candidate (0.0-1.0).

        Learning value is high when:
        - Technique has never been tested (full learning potential)
        - Detection confidence is low (room for improvement)
        - Attack success rate is high (undetected attacks = knowledge gap)
        - Few experiments have been run (insufficient data)

        Learning value is low when:
        - Technique is well-tested with high confidence
        - Attack success rate is low (defense is strong)
        - Many experiments already run (diminishing returns)
        """
        if candidate.times_tested == 0:
            return 1.0

        value = 0.0

        # Confidence component: low confidence = high learning value
        value += (1.0 - candidate.detection_confidence) * 0.3

        # Attack success component: high success = high learning value
        value += candidate.attack_success_rate * 0.3

        # Experiment count component: fewer experiments = higher value
        exp_factor = max(0.0, 1.0 - candidate.times_tested / 10.0)
        value += exp_factor * 0.2

        # Gap component: unresolved gap = high learning value
        if candidate.has_unresolved_gap:
            value += 0.2

        return min(1.0, value)

    def _build_explanation(
        self,
        context: SecurityExperienceContext,
        candidate: CandidateExperiment,
        breakdown: dict,
        total: float,
    ) -> str:
        """Build a human-readable explanation of the score."""
        parts = []
        parts.append(
            f"Strategy '{candidate.strategy_name}' "
            f"(techniques: {', '.join(candidate.technique_ids)})"
        )

        if breakdown.get("unresolved_gap"):
            parts.append(
                f"+{breakdown['unresolved_gap']:.0f}: unresolved detection gap exists"
            )
        if breakdown.get("defense_failed"):
            parts.append(
                f"+{breakdown['defense_failed']:.0f}: previous remediation attempt failed"
            )
        if breakdown.get("never_tested"):
            parts.append(
                f"+{breakdown['never_tested']:.0f}: technique has never been tested"
            )
        if breakdown.get("not_detected"):
            parts.append(
                f"+{breakdown['not_detected']:.0f}: technique was previously not detected"
            )
        if breakdown.get("weak_coverage"):
            parts.append(
                f"+{breakdown['weak_coverage']:.0f}: organization detection coverage is weak ({context.coverage_pct:.1f}%)"
            )
        if breakdown.get("gap_recency_boost"):
            parts.append(
                f"+{breakdown['gap_recency_boost']:.0f}: related to an active detection gap"
            )
        # Upgrade 6 adaptive explanations
        if breakdown.get("detection_gap_magnitude"):
            parts.append(
                f"+{breakdown['detection_gap_magnitude']:.1f}: low detection confidence ({candidate.detection_confidence:.1%})"
            )
        if breakdown.get("attack_success_history"):
            parts.append(
                f"+{breakdown['attack_success_history']:.1f}: high attack success rate ({candidate.attack_success_rate:.1%})"
            )
        if breakdown.get("novelty_boost"):
            parts.append(
                f"+{breakdown['novelty_boost']:.1f}: novel technique (not recently tested)"
            )
        if breakdown.get("learning_value"):
            parts.append(
                f"+{breakdown['learning_value']:.1f}: high expected learning value"
            )
        if breakdown.get("deprioritize_detected"):
            parts.append(
                f"{breakdown['deprioritize_detected']:.0f}: technique already successfully detected"
            )
        if breakdown.get("deprioritize_redundant"):
            parts.append(
                f"{breakdown['deprioritize_redundant']:.0f}: technique tested {candidate.times_tested} times with consistent detection"
            )
        if breakdown.get("deprioritize_recently_tested"):
            parts.append(
                f"{breakdown['deprioritize_recently_tested']:.0f}: tested recently ({candidate.last_tested_days_ago}d ago)"
            )
        if breakdown.get("deprioritize_stale_confidence"):
            parts.append(
                f"{breakdown['deprioritize_stale_confidence']:.0f}: high confidence with low attack success — diminishing returns"
            )

        parts.append(f"Total score: {total:.1f}")
        return "; ".join(parts)
