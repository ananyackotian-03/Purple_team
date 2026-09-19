"""
SentinelForge Phase 3/4/5 Bridge — Scenario-Level Detection Gap Evaluator

Correlates executed ActionIR actions, scenario identities, normalized telemetry
events, and SigmaEngine evaluation results to produce structured per-action and
scenario-level DetectionOutcome objects.

SECURITY INVARIANTS:
- Evaluator is STRICTLY READ-ONLY with respect to execution.
- Evaluator MUST NOT execute commands, modify ActionIR, modify SignedBlueprint,
  bypass PolicyEngine or ExperimentSafetyBoundary, or alter telemetry.
- Evaluator is FAIL-CLOSED: Missing evidence or technique mismatch yields DETECTION_GAP
  or NOT_DETECTED, never a false DETECTED claim.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
import json
import logging
from typing import Dict, List, Optional, Set, Union
from uuid import UUID, uuid4


def _utc_now_iso() -> str:
    """Return a compliant ISO 8601 UTC timestamp with 'Z' suffix."""
    now = datetime.now(timezone.utc)
    return now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"

from sentinelforge.domain.action_ir import ActionIR
from sentinelforge.detection.normalizer import NormalizedEvent
from sentinelforge.detection.sigma_engine import SigmaEngine, DetectionOutcome, DetectionResult

logger = logging.getLogger(__name__)


@dataclass
class ActionDetectionOutcome:
    """Detection outcome for a single executed ActionIR within a scenario."""
    action_id: str
    technique_id: str
    outcome: DetectionOutcome
    matched_rule_ids: List[str] = field(default_factory=list)
    evidence_event_ids: List[str] = field(default_factory=list)
    reason: str = ""
    timestamp: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict:
        """Serialize outcome to a clean dictionary for Phase 5 consumption."""
        d = asdict(self)
        d["outcome"] = self.outcome.value if isinstance(self.outcome, DetectionOutcome) else str(self.outcome)
        return d


@dataclass
class ScenarioDetectionOutcome:
    """Scenario-level detection correlation outcome containing per-action evidence."""
    scenario_id: str
    organization_id: Optional[str]
    overall_outcome: DetectionOutcome
    action_outcomes: List[ActionDetectionOutcome] = field(default_factory=list)
    gap_action_ids: List[str] = field(default_factory=list)
    reason: str = ""
    timestamp: str = field(default_factory=lambda: _utc_now_iso())

    def to_dict(self) -> dict:
        """Serialize scenario outcome to a clean dictionary for Phase 5 consumption."""
        return {
            "scenario_id": str(self.scenario_id),
            "organization_id": str(self.organization_id) if self.organization_id else None,
            "overall_outcome": self.overall_outcome.value if isinstance(self.overall_outcome, DetectionOutcome) else str(self.overall_outcome),
            "action_outcomes": [a.to_dict() for a in self.action_outcomes],
            "gap_action_ids": [str(gid) for gid in self.gap_action_ids],
            "reason": self.reason,
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        """Serialize scenario outcome to JSON string."""
        return json.dumps(self.to_dict(), indent=2)


class DetectionGapEvaluator:
    """Deterministic, scenario-level telemetry and detection correlator.

    Bridges Red Agent ActionIR execution with SigmaEngine detection results.
    """

    def evaluate_action(
        self,
        action: ActionIR,
        events: List[NormalizedEvent],
        sigma_engine: SigmaEngine,
        correlation_id: Optional[Union[str, UUID]] = None,
    ) -> ActionDetectionOutcome:
        """Evaluate defensive detection evidence for a single executed ActionIR.

        Args:
            action: Executed ActionIR model.
            events: Candidate normalized telemetry events.
            sigma_engine: Loaded SigmaEngine instance.
            correlation_id: Optional correlation identifier (scenario or action ID).

        Returns:
            ActionDetectionOutcome containing DETECTED, NOT_DETECTED, or DETECTION_GAP.
        """
        action_id_str = str(action.action_id)
        expected_tech_id = str(action.technique_id).strip()
        ts_now = _utc_now_iso()
        target_corr = str(correlation_id).strip() if correlation_id else None

        # 1. Filter events based on correlation ID (Scenario Isolation)
        scoped_events = []
        seen_keys: Set[str] = set()

        for ev in events:
            # Rule 3: Malformed telemetry safety
            if not isinstance(ev, NormalizedEvent) or not ev.event_id:
                continue

            # Rule 2: Deduplicate telemetry
            dedup_key = f"{ev.event_id}:{ev.raw_event_hash}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)

            # Rule 1: Scenario Isolation
            if target_corr:
                if ev.correlation_id and str(ev.correlation_id).strip() != target_corr:
                    # Event belongs to another scenario or execution context -> isolate!
                    continue

            # Check action relevance
            if self._is_event_relevant_to_action(ev, action):
                scoped_events.append(ev)

        # 2. Rule 6: Evidence Requirement — Check if telemetry exists
        if not scoped_events:
            return ActionDetectionOutcome(
                action_id=action_id_str,
                technique_id=expected_tech_id,
                outcome=DetectionOutcome.DETECTION_GAP,
                matched_rule_ids=[],
                evidence_event_ids=[],
                reason=f"No relevant telemetry events captured for technique {expected_tech_id}",
                timestamp=ts_now,
            )

        # 3. Evaluate scoped telemetry events with SigmaEngine
        matched_rule_ids: List[str] = []
        evidence_event_ids: List[str] = []
        unrelated_matches: List[str] = []

        for ev in scoped_events:
            sigma_dict = ev.to_sigma_dict()
            results = sigma_engine.evaluate(
                sigma_dict,
                event_id=ev.event_id,
                correlation_id=ev.correlation_id or target_corr,
            )

            for res in results:
                if res.matched:
                    rule_tech = str(res.technique_id).strip()
                    # Rule 4 & 5: Check Technique ID match
                    if self._technique_matches(rule_tech, expected_tech_id):
                        if res.rule_id not in matched_rule_ids:
                            matched_rule_ids.append(res.rule_id)
                        if ev.event_id not in evidence_event_ids:
                            evidence_event_ids.append(ev.event_id)
                    else:
                        unrelated_matches.append(f"{res.rule_id} ({rule_tech})")

        # 4. Determine final outcome for action
        if matched_rule_ids:
            return ActionDetectionOutcome(
                action_id=action_id_str,
                technique_id=expected_tech_id,
                outcome=DetectionOutcome.DETECTED,
                matched_rule_ids=matched_rule_ids,
                evidence_event_ids=evidence_event_ids,
                reason=f"Detected by Sigma rule(s): {', '.join(matched_rule_ids)} for technique {expected_tech_id}",
                timestamp=ts_now,
            )

        if unrelated_matches:
            # Telemetry was observed and Sigma rule matched, but for an UNRELATED technique!
            return ActionDetectionOutcome(
                action_id=action_id_str,
                technique_id=expected_tech_id,
                outcome=DetectionOutcome.NOT_DETECTED,
                matched_rule_ids=[],
                evidence_event_ids=[ev.event_id for ev in scoped_events],
                reason=f"Telemetry observed and matched unrelated rule(s) [{', '.join(unrelated_matches)}], but expected technique {expected_tech_id} was not detected",
                timestamp=ts_now,
            )

        # Telemetry observed relevant to action, but no Sigma rule matched
        return ActionDetectionOutcome(
            action_id=action_id_str,
            technique_id=expected_tech_id,
            outcome=DetectionOutcome.NOT_DETECTED,
            matched_rule_ids=[],
            evidence_event_ids=[ev.event_id for ev in scoped_events],
            reason=f"Telemetry observed for action, but no Sigma rule matched technique {expected_tech_id}",
            timestamp=ts_now,
        )

    def evaluate_scenario(
        self,
        scenario_id: Union[str, UUID],
        actions: List[ActionIR],
        events: List[NormalizedEvent],
        sigma_engine: SigmaEngine,
        organization_id: Optional[Union[str, UUID]] = None,
    ) -> ScenarioDetectionOutcome:
        """Evaluate detection outcomes across all executed ActionIR actions in a scenario.

        Args:
            scenario_id: Identifier for the adversarial scenario.
            actions: List of executed ActionIR actions.
            events: List of normalized telemetry events.
            sigma_engine: Loaded SigmaEngine instance.
            organization_id: Optional organization tenant identifier.

        Returns:
            ScenarioDetectionOutcome summarizing overall scenario detection.
        """
        scenario_id_str = str(scenario_id)
        org_id_str = str(organization_id) if organization_id else None
        ts_now = _utc_now_iso()

        if not actions:
            return ScenarioDetectionOutcome(
                scenario_id=scenario_id_str,
                organization_id=org_id_str,
                overall_outcome=DetectionOutcome.DETECTION_GAP,
                action_outcomes=[],
                gap_action_ids=[],
                reason="No executed actions provided for scenario evaluation",
                timestamp=ts_now,
            )

        action_outcomes: List[ActionDetectionOutcome] = []
        gap_action_ids: List[str] = []

        for action in actions:
            act_outcome = self.evaluate_action(
                action=action,
                events=events,
                sigma_engine=sigma_engine,
                correlation_id=scenario_id_str,
            )
            action_outcomes.append(act_outcome)

            if act_outcome.outcome != DetectionOutcome.DETECTED:
                gap_action_ids.append(act_outcome.action_id)

        # Scenario level: DETECTED iff ALL actions are DETECTED
        if not gap_action_ids:
            overall = DetectionOutcome.DETECTED
            reason = f"All {len(actions)} scenario actions were successfully detected"
        else:
            overall = DetectionOutcome.DETECTION_GAP
            reason = f"Detection gap identified: {len(gap_action_ids)} of {len(actions)} action(s) missed detection ({', '.join(gap_action_ids)})"

        return ScenarioDetectionOutcome(
            scenario_id=scenario_id_str,
            organization_id=org_id_str,
            overall_outcome=overall,
            action_outcomes=action_outcomes,
            gap_action_ids=gap_action_ids,
            reason=reason,
            timestamp=ts_now,
        )

    def _is_event_relevant_to_action(self, ev: NormalizedEvent, action: ActionIR) -> bool:
        """Determine if a telemetry event is relevant to an ActionIR execution."""
        # Container check (if populated)
        if ev.ContainerName and action.target:
            if ev.ContainerName.lower() != action.target.lower() and action.target.lower() not in ev.ContainerName.lower():
                return False

        # User check (if populated)
        if ev.UserName and action.run_as_user:
            if ev.UserName.lower() != action.run_as_user.lower():
                return False

        # Command arguments / process / target file matching
        cmd_args = " ".join(action.arguments) if action.arguments else action.executable
        cmd_args_lower = cmd_args.lower()
        exe_lower = action.executable.lower()
        tech_id = str(action.technique_id).upper()

        ev_cmd = (ev.CommandLine or "").lower()
        ev_proc = (ev.ProcessName or "").lower()
        ev_exe = (ev.Executable or "").lower()
        ev_file = (ev.TargetFile or "").lower()
        ev_type = (ev.EventType or "").lower()

        # Specific technique heuristics
        if "T1003.008" in tech_id or "shadow" in cmd_args_lower:
            return "shadow" in ev_file or "shadow" in ev_cmd or ev_proc == "cat"
        if "T1070.004" in tech_id or "rm " in cmd_args_lower:
            return ev_type == "unlinkat" or "rm" in ev_cmd or ev_proc == "rm"
        if "T1059.004" in tech_id or "bash" in exe_lower or "whoami" in cmd_args_lower or "id" in cmd_args_lower:
            return (
                ev_proc in ("bash", "sh", "whoami", "id")
                or "bash" in ev_exe
                or "whoami" in ev_cmd
                or "id" in ev_cmd
                or "bash" in ev_cmd
            )

        # General token match
        tokens = [t for t in cmd_args_lower.replace("-c", "").replace("/", " ").split() if len(t) > 2]
        for tok in tokens:
            if tok in ev_cmd or tok in ev_proc or tok in ev_exe or tok in ev_file:
                return True

        return False

    def _technique_matches(self, rule_tech: str, expected_tech: str) -> bool:
        """Check if a Sigma rule technique matches the expected action technique ID."""
        r_tech = rule_tech.strip().upper()
        e_tech = expected_tech.strip().upper()

        if not r_tech or r_tech == "UNKNOWN":
            return False

        if r_tech == e_tech:
            return True

        # Handle sub-technique prefix match (e.g. T1059.004 matches T1059 or vice versa)
        if r_tech.startswith(e_tech) or e_tech.startswith(r_tech):
            return True

        return False


# ---------------------------------------------------------------------------
# Purple Evaluation — Deterministic experiment-level detection verdict
# ---------------------------------------------------------------------------

@dataclass
class PurpleEvaluation:
    """Deterministic evaluation of one eligible experiment/scenario.

    One PurpleEvaluation per experiment/scenario — NEVER per action.
    The `expected_detection` field is metadata only and MUST NOT
    influence the `detection_status` value.
    """
    evaluation_id: str
    experiment_id: str              # scenario_id
    execution_id: str               # blueprint_id
    organization_id: str
    technique_id: str
    detection_status: str           # DETECTED | NOT_DETECTED | DETECTION_GAP
    matched_rule_ids: List[str] = field(default_factory=list)
    evidence_event_ids: List[str] = field(default_factory=list)
    expected_detection: bool = False
    gap_reason: Optional[str] = None
    detection_latency_ms: Optional[float] = None
    evaluated_at: str = field(default_factory=lambda: _utc_now_iso())

    def to_dict(self) -> dict:
        return {
            "evaluation_id": self.evaluation_id,
            "experiment_id": self.experiment_id,
            "execution_id": self.execution_id,
            "organization_id": self.organization_id,
            "technique_id": self.technique_id,
            "detection_status": self.detection_status,
            "matched_rule_ids": self.matched_rule_ids,
            "evidence_event_ids": self.evidence_event_ids,
            "expected_detection": self.expected_detection,
            "gap_reason": self.gap_reason,
            "detection_latency_ms": self.detection_latency_ms,
            "evaluated_at": self.evaluated_at,
        }


@dataclass
class CoverageReport:
    """Aggregate detection coverage across eligible experiments for one organization.

    Coverage = detected eligible experiments / eligible experiments * 100.
    Safe for zero eligible experiments (coverage_pct = 0.0).
    """
    report_id: str
    organization_id: str
    total_experiments: int
    detected_experiments: int
    missed_experiments: int
    gap_experiments: int
    coverage_pct: float
    technique_coverage: Dict[str, bool] = field(default_factory=dict)
    evaluations: List[PurpleEvaluation] = field(default_factory=list)
    generated_at: str = field(default_factory=lambda: _utc_now_iso())

    def to_dict(self) -> dict:
        return {
            "report_id": self.report_id,
            "organization_id": self.organization_id,
            "total_experiments": self.total_experiments,
            "detected_experiments": self.detected_experiments,
            "missed_experiments": self.missed_experiments,
            "gap_experiments": self.gap_experiments,
            "coverage_pct": self.coverage_pct,
            "technique_coverage": self.technique_coverage,
            "generated_at": self.generated_at,
        }


class PurpleEvaluator:
    """Deterministic Purple Evaluation engine.

    Consumes existing ScenarioDetectionOutcome data and produces
    PurpleEvaluation verdicts and CoverageReport metrics.

    SECURITY INVARIANTS:
    - detection_status is derived SOLELY from the DetectionEngine result.
    - expected_detection is metadata only and NEVER influences detection_status.
    - Coverage is computed deterministically; no LLM participation.
    - Organization scoping is enforced; no cross-tenant aggregation.
    """

    def evaluate(
        self,
        scenario_outcome: ScenarioDetectionOutcome,
        actions: List[ActionIR],
        execution_id: Optional[str] = None,
        expected_detection: bool = False,
    ) -> PurpleEvaluation:
        """Produce a single PurpleEvaluation for one experiment/scenario.

        Args:
            scenario_outcome: Detection result from DetectionGapEvaluator.
            actions: Executed ActionIR actions for this experiment.
            execution_id: Optional blueprint/execution identifier.
            expected_detection: LLM metadata claim — never determines status.

        Returns:
            PurpleEvaluation with deterministic detection_status.
        """
        org_id = str(scenario_outcome.organization_id) if scenario_outcome.organization_id else ""
        scenario_id = str(scenario_outcome.scenario_id)
        ts_now = _utc_now_iso()

        # Aggregate matched rules and evidence from ALL action outcomes
        all_matched_rules: List[str] = []
        all_evidence_ids: List[str] = []
        all_technique_ids: List[str] = []
        gap_reasons: List[str] = []

        for act_out in scenario_outcome.action_outcomes:
            for rid in act_out.matched_rule_ids:
                if rid not in all_matched_rules:
                    all_matched_rules.append(rid)
            for eid in act_out.evidence_event_ids:
                if eid not in all_evidence_ids:
                    all_evidence_ids.append(eid)
            if act_out.technique_id and act_out.technique_id not in all_technique_ids:
                all_technique_ids.append(act_out.technique_id)
            if act_out.outcome != DetectionOutcome.DETECTED and act_out.reason:
                gap_reasons.append(act_out.reason)

        # Derive detection_status from ACTUAL detection outcome only
        detection_status = scenario_outcome.overall_outcome.value

        # Primary technique: most common or first action technique
        primary_technique = all_technique_ids[0] if all_technique_ids else "unknown"

        # Gap reason: aggregate non-detected reasons
        gap_reason = "; ".join(gap_reasons) if gap_reasons else None

        # Calculate detection latency from scenario timestamps if available
        latency_ms = None
        if scenario_outcome.action_outcomes:
            try:
                first_ts = scenario_outcome.action_outcomes[0].timestamp
                # Parse timestamps, handling Z-suffixed, +00:00, and legacy +00:00Z formats
                def _parse_ts(ts_str: str) -> datetime:
                    # Remove trailing Z to avoid double-offset with legacy +00:00Z format
                    clean = ts_str.rstrip("Z")
                    dt = datetime.fromisoformat(clean)
                    if dt.tzinfo is None:
                        dt = dt.replace(tzinfo=timezone.utc)
                    return dt

                start = _parse_ts(first_ts)
                end = _parse_ts(ts_now)
                latency_ms = max(0.0, (end - start).total_seconds() * 1000)
            except (ValueError, TypeError):
                latency_ms = None

        return PurpleEvaluation(
            evaluation_id=str(uuid4()),
            experiment_id=scenario_id,
            execution_id=execution_id or "",
            organization_id=org_id,
            technique_id=primary_technique,
            detection_status=detection_status,
            matched_rule_ids=all_matched_rules,
            evidence_event_ids=all_evidence_ids,
            expected_detection=expected_detection,
            gap_reason=gap_reason,
            detection_latency_ms=latency_ms,
            evaluated_at=ts_now,
        )

    def compute_coverage(
        self,
        evaluations: List[PurpleEvaluation],
        organization_id: str,
    ) -> CoverageReport:
        """Aggregate PurpleEvaluation records into a CoverageReport.

        Coverage = detected eligible experiments / eligible experiments * 100.
        Organization scoping: only evaluations matching organization_id are counted.
        """
        org_evals = [e for e in evaluations if e.organization_id == organization_id]
        total = len(org_evals)
        detected = sum(1 for e in org_evals if e.detection_status == DetectionOutcome.DETECTED.value)
        missed = sum(1 for e in org_evals if e.detection_status == DetectionOutcome.NOT_DETECTED.value)
        gap = sum(1 for e in org_evals if e.detection_status == DetectionOutcome.DETECTION_GAP.value)

        coverage_pct = (detected / total * 100.0) if total > 0 else 0.0

        # Technique-level coverage: True if any evaluation for that technique is DETECTED
        tech_coverage: Dict[str, bool] = {}
        for e in org_evals:
            tech = e.technique_id
            if tech not in tech_coverage:
                tech_coverage[tech] = False
            if e.detection_status == DetectionOutcome.DETECTED.value:
                tech_coverage[tech] = True

        return CoverageReport(
            report_id=str(uuid4()),
            organization_id=organization_id,
            total_experiments=total,
            detected_experiments=detected,
            missed_experiments=missed,
            gap_experiments=gap,
            coverage_pct=coverage_pct,
            technique_coverage=tech_coverage,
            evaluations=org_evals,
        )
