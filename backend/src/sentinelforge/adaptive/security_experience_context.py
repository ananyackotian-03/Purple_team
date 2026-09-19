"""Phase 10 + Upgrade 6 — Security Experience Context Builder.

Builds a deterministic context summarizing the organization's security
history for next-experiment selection. All data is derived from persisted
records via ImmuneMemory and OrganizationSecurityState. No LLM input
influences the computed context.

Upgrade 6 adds:
- Detection gap profiles per technique
- Adaptive fields on candidates (detection_confidence, attack_success_rate, etc.)
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID

from sentinelforge.adaptive.schemas import (
    CandidateExperiment,
    CandidateStatus,
    DetectionGapProfile,
    SecurityExperienceContext,
)
from sentinelforge.immune_memory import ImmuneMemory
from sentinelforge.organization.security_state import OrganizationSecurityState

# Import the STRATEGY_CATALOG for candidate generation
from sentinelforge.agents.red_agent import STRATEGY_CATALOG


class SecurityExperienceContextBuilder:
    """Builds SecurityExperienceContext from persisted organizational state.

    Queries ImmuneMemory and OrganizationSecurityState to produce a
    deterministic snapshot of the organization's security posture and
    available experiment candidates. All queries are tenant-scoped by
    organization_id.
    """

    def __init__(self, db_session: Any, organization_id: UUID):
        self.db_session = db_session
        self.organization_id = organization_id
        self.immune_memory = ImmuneMemory(db_session, organization_id)
        self.org_security_state = OrganizationSecurityState(db_session, organization_id)

    @staticmethod
    def _extract_risk_level(strat_info: dict) -> str:
        """Extract risk level string from STRATEGY_CATALOG entry.

        RiskLevel enum values serialize as 'RiskLevel.MEDIUM' when str()
        is called; this extracts just the level name.
        """
        raw = strat_info.get("proposed_risk_level", "MEDIUM")
        if hasattr(raw, "value"):
            return raw.value
        raw_str = str(raw)
        if "." in raw_str:
            return raw_str.rsplit(".", 1)[-1]
        return raw_str

    def build(self) -> SecurityExperienceContext:
        """Build the complete security experience context.

        Returns:
            SecurityExperienceContext with all fields populated from
            persisted records. Upgrade 6 adds gap profiles and adaptive
            candidate fields.
        """
        # Build technique-level detail from purple evaluations
        techniques_detected, techniques_missed, techniques_with_gap = (
            self._categorize_techniques()
        )

        # Build detection gap profiles (Upgrade 6)
        from sentinelforge.adaptive.detection_gap_model import DetectionGapModel
        gap_model = DetectionGapModel(self.db_session, self.organization_id)
        gap_profiles = gap_model.build_gap_profiles()

        # Build candidates from STRATEGY_CATALOG + history
        candidates = self._build_candidates(gap_profiles)

        # Compute aggregate state from ImmuneMemory
        immune_state = self.immune_memory.compute_state()

        return SecurityExperienceContext(
            organization_id=str(self.organization_id),
            built_at=datetime.now(timezone.utc).isoformat() + "Z",
            total_experiments=self.immune_memory.previous_experiments,
            coverage_pct=round(self.immune_memory.coverage_pct, 1),
            detected_experiments=immune_state.get("detected_experiments", 0),
            missed_experiments=immune_state.get("missed_experiments", 0),
            detection_gap_experiments=immune_state.get("detection_gap_experiments", 0),
            unresolved_gaps=self.immune_memory.unresolved_gaps,
            mitigated_gaps=self.immune_memory.mitigated_gaps,
            techniques_tested=self.immune_memory.techniques_tested,
            techniques_detected=techniques_detected,
            techniques_missed=techniques_missed,
            techniques_with_gap=techniques_with_gap,
            detection_gaps=immune_state.get("detection_gaps", []),
            retest_results=immune_state.get("retest_results", []),
            successful_improvements=immune_state.get("successful_improvements", 0),
            failed_improvements=immune_state.get("failed_improvements", 0),
            defensive_proposals=immune_state.get("defensive_proposals", []),
            candidates=candidates,
            gap_profiles=gap_profiles,
        )

    def _categorize_techniques(self) -> tuple:
        """Categorize techniques by their detection status.

        Returns (detected, missed, with_gap) lists of technique IDs.
        """
        from sentinelforge.db.models import PurpleEvaluationRecord

        evaluations = (
            self.db_session.query(PurpleEvaluationRecord)
            .filter(PurpleEvaluationRecord.organization_id == self.organization_id)
            .all()
        )

        detected = set()
        missed = set()
        with_gap = set()

        for eval_rec in evaluations:
            tech = eval_rec.technique_id
            if not tech:
                continue
            status = eval_rec.detection_status
            if status == "DETECTED":
                detected.add(tech)
            elif status == "NOT_DETECTED":
                missed.add(tech)
            elif status == "DETECTION_GAP":
                with_gap.add(tech)

        return sorted(detected), sorted(missed), sorted(with_gap)

    def _build_candidates(
        self,
        gap_profiles: List[DetectionGapProfile] = None,
    ) -> List[CandidateExperiment]:
        """Build candidate experiments from STRATEGY_CATALOG enriched with history.

        Each strategy in the catalog becomes a candidate, annotated with
        testing history from ImmuneMemory. Upgrade 6 adds adaptive fields
        from detection gap profiles.
        """
        # Load history data
        tested_techniques = set(self.immune_memory.techniques_tested)
        detection_gaps = self.immune_memory.detection_gaps
        retest_results = self.immune_memory.retest_results
        purple_evals = self.org_security_state._get_purple_evaluations()

        # Build per-technique history maps
        tech_test_counts: Dict[str, int] = {}
        tech_detected_counts: Dict[str, int] = {}
        tech_not_detected_counts: Dict[str, int] = {}
        tech_gap_ids: Dict[str, List[str]] = {}
        tech_last_tested: Dict[str, Optional[str]] = {}

        for eval_rec in purple_evals:
            tech = eval_rec.technique_id
            if not tech:
                continue
            tech_test_counts[tech] = tech_test_counts.get(tech, 0) + 1
            status = eval_rec.detection_status
            if status == "DETECTED":
                tech_detected_counts[tech] = tech_detected_counts.get(tech, 0) + 1
            elif status in ("NOT_DETECTED", "DETECTION_GAP"):
                tech_not_detected_counts[tech] = tech_not_detected_counts.get(tech, 0) + 1
            ts = eval_rec.evaluated_at
            if ts:
                ts_str = ts.isoformat() if hasattr(ts, "isoformat") else str(ts)
                if tech not in tech_last_tested or ts_str > (tech_last_tested[tech] or ""):
                    tech_last_tested[tech] = ts_str

        # Track unresolved gap technique IDs
        unresolved_gap_techniques: set = set()
        for gap in detection_gaps:
            tech = gap.technique_id
            status = gap.remediation_status
            if status in ("OPEN", "UNRESOLVED"):
                unresolved_gap_techniques.add(tech)
                tech_gap_ids.setdefault(tech, []).append(str(gap.id))

        # Track techniques where defense failed
        failed_defense_techniques: set = set()
        for retest in retest_results:
            if hasattr(retest, "before_outcome") and hasattr(retest, "after_outcome"):
                if retest.before_outcome and retest.after_outcome:
                    if retest.before_outcome == retest.after_outcome:
                        # No improvement — defense failed
                        # Find the technique from the gap record
                        pass

        # Build a lookup from gap profiles
        profile_lookup: Dict[str, DetectionGapProfile] = {}
        if gap_profiles:
            for p in gap_profiles:
                profile_lookup[p.technique_id] = p

        # Build candidates from STRATEGY_CATALOG
        candidates = []
        for strategy_name, strat_info in STRATEGY_CATALOG.items():
            technique_ids = strat_info.get("technique_ids", [])
            if not technique_ids:
                continue

            # Determine candidate status based on history
            times_tested = sum(tech_test_counts.get(t, 0) for t in technique_ids)
            times_detected = sum(tech_detected_counts.get(t, 0) for t in technique_ids)
            times_not_detected = sum(tech_not_detected_counts.get(t, 0) for t in technique_ids)
            has_unresolved = any(t in unresolved_gap_techniques for t in technique_ids)
            defense_failed = any(t in failed_defense_techniques for t in technique_ids)

            # Determine the overall candidate status
            candidate_status = self._determine_candidate_status(
                technique_ids=technique_ids,
                times_tested=times_tested,
                times_detected=times_detected,
                times_not_detected=times_not_detected,
                has_unresolved_gap=has_unresolved,
                defense_failed=defense_failed,
                tested_techniques=tested_techniques,
            )

            # Collect related gap IDs
            related_gaps = []
            for t in technique_ids:
                related_gaps.extend(tech_gap_ids.get(t, []))

            # Last tested time
            last_tested = None
            for t in technique_ids:
                lt = tech_last_tested.get(t)
                if lt and (last_tested is None or lt > last_tested):
                    last_tested = lt

            # Upgrade 6 — Compute adaptive fields from gap profiles
            detection_confidence, attack_success_rate, last_tested_days_ago, recent_count = (
                self._compute_adaptive_fields(technique_ids, profile_lookup, last_tested)
            )

            candidates.append(CandidateExperiment(
                strategy_name=strategy_name,
                technique_ids=technique_ids,
                title=strat_info.get("title", strategy_name),
                description=strat_info.get("description", ""),
                proposed_risk_level=self._extract_risk_level(strat_info),
                candidate_status=candidate_status,
                times_tested=times_tested,
                times_detected=times_detected,
                times_not_detected=times_not_detected,
                has_unresolved_gap=has_unresolved,
                defense_failed=defense_failed,
                last_tested_at=last_tested,
                related_gap_ids=related_gaps,
                detection_confidence=detection_confidence,
                attack_success_rate=attack_success_rate,
                last_tested_days_ago=last_tested_days_ago,
                recent_experiment_count=recent_count,
            ))

        return candidates

    @staticmethod
    def _compute_adaptive_fields(
        technique_ids: List[str],
        profile_lookup: Dict[str, DetectionGapProfile],
        last_tested: Optional[str],
    ) -> tuple:
        """Compute adaptive scoring fields for a candidate from gap profiles.

        Aggregates across all technique IDs for the candidate.
        Returns (detection_confidence, attack_success_rate, last_tested_days_ago, recent_count).
        """
        total_conf = 0.0
        total_attack = 0.0
        min_days_ago = None
        total_recent = 0
        count = 0

        now = datetime.now(timezone.utc)

        for tech in technique_ids:
            profile = profile_lookup.get(tech)
            if profile:
                total_conf += profile.detection_confidence
                total_attack += profile.attack_success_rate
                total_recent += profile.recent_experiment_count
                if profile.last_tested_days_ago is not None:
                    if min_days_ago is None or profile.last_tested_days_ago < min_days_ago:
                        min_days_ago = profile.last_tested_days_ago
                count += 1

        if count > 0:
            avg_conf = total_conf / count
            avg_attack = total_attack / count
        else:
            # No profile data — compute from last_tested string
            avg_conf = 0.0
            avg_attack = 0.0
            if last_tested:
                try:
                    dt = datetime.fromisoformat(last_tested.replace("Z", "+00:00"))
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    min_days_ago = max(0, (now - dt).days)
                except (ValueError, TypeError):
                    pass

        return (
            round(avg_conf, 4),
            round(avg_attack, 4),
            min_days_ago,
            total_recent,
        )

    def _determine_candidate_status(
        self,
        technique_ids: List[str],
        times_tested: int,
        times_detected: int,
        times_not_detected: int,
        has_unresolved_gap: bool,
        defense_failed: bool,
        tested_techniques: set,
    ) -> CandidateStatus:
        """Deterministically derive the candidate status from history."""
        all_tested = all(t in tested_techniques for t in technique_ids)

        if has_unresolved_gap:
            return CandidateStatus.UNRESOLVED_GAP

        if defense_failed:
            return CandidateStatus.PREVIOUSLY_FAILED_DEFENSE

        if not all_tested and times_tested == 0:
            return CandidateStatus.NEVER_TESTED

        if times_not_detected > 0 and times_detected == 0:
            return CandidateStatus.NOT_DETECTED

        if times_detected > 0 and times_not_detected == 0:
            return CandidateStatus.RECENTLY_DETECTED

        # Mixed results — consider as recently tested
        return CandidateStatus.RECENTLY_TESTED
