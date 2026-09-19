"""RedAgent — the LLM-driven orchestrator loop (deterministic control plane).

SECURITY ROLE:
This module owns the closed reasoning-action loop. The LLM proposes; every
proposal is validated in this order:
  1. Strict Pydantic schema validation,
  2. Deterministic novelty evaluation,
  3. ExperimentSafetyBoundary + PolicyEngine (SafetyBoundaryBridge),
  4. (if ALLOWED) HMAC signing and SimulationWorker dispatch.

The LLM NEVER controls state transitions, budget counters, signing, or
execution. Budget limits are enforced here by outer Python code.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, List, Optional
from uuid import uuid4, UUID

logger = logging.getLogger(__name__)

from sentinelforge.agents.red.context import ContextBuilder, RedAgentContext
from sentinelforge.agents.red.exceptions import (
    BudgetExhaustedError,
    RedAgentException,
    SchemaValidationError,
)
from sentinelforge.agents.red.memory import RedAgentMemoryStore
from sentinelforge.agents.red.novelty import (
    NoveltyEvaluator,
    NoveltyStatus,
    StrategyFingerprint,
)
from sentinelforge.agents.red.policies import SafetyBoundaryBridge, SafetyBridgeResult
from sentinelforge.agents.red.prompts import build_system_prompt, build_user_prompt
from sentinelforge.agents.red.provider import LLMProvider
from sentinelforge.agents.red.schemas import RedAgentBudget, RedAgentDecision
from sentinelforge.agents.red.state import RedAgentState, RedAgentStateMachine
from sentinelforge.domain.blueprint import SignedBlueprint
from sentinelforge.domain.experiment import (
    ExperimentConstraints,
    PolicyDecision,
    PolicyDecisionStatus,
    SecurityObjective,
)

# Retry limits (design section 20).
MAX_SCHEMA_RETRIES = 3
MAX_SAFETY_REJECTIONS = 3

# Detection outcomes recorded for memory/strategy updates.
OUTCOME_EXECUTED = "EXECUTED"
OUTCOME_DENIED = "DENIED"
OUTCOME_SKIPPED = "SKIPPED_DUPLICATE"
# Dispatch-time outcomes (Step 2A). The worker boundary is the only place
# execution can be refused or fail once a blueprint has been signed.
OUTCOME_SIMULATION_REJECTED = "SIMULATION_REJECTED"
OUTCOME_SIMULATION_FAILED = "SIMULATION_FAILED"

# Simulation statuses that mean the adapter actually started executing the
# action. Only these executions are eligible for telemetry collection (Step 2B);
# REJECTED/FAILED dispatches never reach execution and never claim telemetry.
EXECUTED_SIMULATION_STATUSES = ("COMPLETED", "TIMEOUT")


@dataclass
class RedAgentConfig:
    """Configuration for a RedAgent run. All execution-critical settings live here."""

    provider: LLMProvider
    budget: RedAgentBudget = field(default_factory=RedAgentBudget)
    constraints: ExperimentConstraints = field(default_factory=ExperimentConstraints)
    bridge: Optional[SafetyBoundaryBridge] = None
    memory: Optional[RedAgentMemoryStore] = None
    novelty: Optional[NoveltyEvaluator] = None
    context_builder: Optional[ContextBuilder] = None
    db_session: Any = None
    max_schema_retries: int = MAX_SCHEMA_RETRIES
    max_safety_rejections: int = MAX_SAFETY_REJECTIONS
    worker: Any = None
    detection_evaluator: Any = None
    sigma_engine: Any = None
    # Step 2B: existing TelemetryCollector + a raw Falco JSON source.
    # `telemetry_source` is an optional callable
    #   Callable[[SimulationExecution], List[str]]
    # returning raw Falco JSON lines for a given execution. When no real Falco
    # transport is available it is omitted (None) and nothing is collected.
    telemetry_collector: Any = None
    telemetry_source: Any = None


@dataclass
class RedAgentRunResult:
    """Summary of a complete objective run."""

    objective: SecurityObjective
    final_state: RedAgentState
    iterations: int = 0
    experiments: int = 0
    llm_calls: int = 0
    decisions: List[RedAgentDecision] = field(default_factory=list)
    policy_decisions: List[PolicyDecision] = field(default_factory=list)
    novelty_evaluations: List[Any] = field(default_factory=list)
    executed_blueprints: List[SignedBlueprint] = field(default_factory=list)
    skipped_strategies: List[str] = field(default_factory=list)
    terminated_reason: str = ""
    escalated: bool = False
    simulation_executions: List[Any] = field(default_factory=list)
    collected_telemetry: List[Any] = field(default_factory=list)
    detection_outcome: Any = None


class RedAgent:
    """Closed-loop Red Agent orchestrator.

    The `worker`, `detection_evaluator`, and `sigma_engine` are optional. When
    absent (unit-test mode) ALLOWED experiments are recorded as executed
    without dispatching to a live sandbox, so the full control-plane path can
    be exercised deterministically.
    """

    def __init__(self, config: RedAgentConfig):
        self.config = config
        self._state = RedAgentStateMachine()
        self._budget = config.budget
        self._bridge = config.bridge or SafetyBoundaryBridge(
            constraints=config.constraints
        )
        self._memory = config.memory or RedAgentMemoryStore(db_session=config.db_session)
        self._novelty = config.novelty or NoveltyEvaluator()
        self._context_builder = config.context_builder or ContextBuilder(
            db_session=config.db_session
        )
        self._started_at: Optional[datetime] = None

    def run(
        self,
        objective: SecurityObjective,
        is_human_approved: bool = False,
        untrusted_telemetry: Optional[list] = None,
    ) -> RedAgentRunResult:
        """Execute the full objective exploration loop."""
        self._started_at = datetime.now(timezone.utc)
        result = RedAgentRunResult(objective=objective, final_state=RedAgentState.IDLE)

        try:
            self._budget.assert_has_remaining(0, 0, 0, self._started_at)
        except BudgetExhaustedError as exc:
            result.final_state = RedAgentState.FINISHED
            result.terminated_reason = str(exc)
            return result

        self._state.transition(RedAgentState.OBJECTIVE_RECEIVED)
        self._state.transition(RedAgentState.CONTEXT_LOADING)

        safety_rejections = 0
        last_feedback: Optional[str] = None

        while True:
            if self._state.state in (RedAgentState.FINISHED,):
                result.final_state = self._state.state
                return result

            # Enter ANALYZING on the first iteration (from CONTEXT_LOADING).
            # Every `continue` path already leaves the machine in ANALYZING.
            if self._state.state != RedAgentState.ANALYZING:
                self._state.transition(RedAgentState.ANALYZING)

            try:
                self._budget.assert_has_remaining(
                    result.iterations,
                    result.experiments,
                    result.llm_calls,
                    self._started_at,
                )
            except BudgetExhaustedError as exc:
                result.final_state = RedAgentState.FINISHED
                result.terminated_reason = str(exc)
                return result

            if safety_rejections >= self.config.max_safety_rejections:
                result.final_state = RedAgentState.FINISHED
                result.terminated_reason = (
                    f"Exceeded {self.config.max_safety_rejections} consecutive "
                    "safety rejections."
                )
                return result

            decision = self._obtain_decision(objective, result, untrusted_telemetry, last_feedback)
            if decision is None:
                result.final_state = RedAgentState.FINISHED
                result.terminated_reason = "LLM decision unavailable after schema retries."
                return result

            self._state.transition(RedAgentState.HYPOTHESIS_GENERATED)
            result.decisions.append(decision)

            if decision.decision == "TERMINATE_OBJECTIVE":
                self._state.transition(RedAgentState.FINISHED)
                result.final_state = RedAgentState.FINISHED
                result.terminated_reason = "TERMINATE_OBJECTIVE returned by LLM."
                return result

            # SCENARIO_GENERATED
            scenario_proposal = decision.scenario
            self._state.transition(RedAgentState.SCENARIO_GENERATED)

            # NOVELTY_CHECK
            self._state.transition(RedAgentState.NOVELTY_CHECK)
            fingerprint = StrategyFingerprint.create(
                objective.objective_id, scenario_proposal.proposed_actions
            )
            novelty = self._novelty.evaluate(fingerprint)
            result.novelty_evaluations.append(novelty)

            if novelty.status != NoveltyStatus.NOVEL:
                result.skipped_strategies.append(fingerprint.composite_hash)
                self._memory.record_strategy(
                    organization_id=objective.organization_id,
                    objective_id=objective.objective_id,
                    scenario_id=result.policy_decisions[-1].scenario_id
                    if result.policy_decisions
                    else objective.objective_id,
                    fingerprint=fingerprint,
                    outcome=OUTCOME_SKIPPED,
                )
                self._novelty.register(fingerprint)
                result.iterations += 1
                last_feedback = f"Previous proposal was {novelty.status.value}; refine it."
                if self._state.can_transition(RedAgentState.REFINE):
                    self._state.transition(RedAgentState.REFINE)
                self._state.transition(RedAgentState.ANALYZING)
                continue

            # SAFETY_SUBMITTED
            self._state.transition(RedAgentState.SAFETY_SUBMITTED)
            bridge_result = self._bridge.evaluate_proposal(
                objective,
                scenario_proposal,
                is_human_approved=is_human_approved,
            )
            result.policy_decisions.append(bridge_result.policy_decision)

            if bridge_result.is_denied:
                result.iterations += 1
                safety_rejections += 1
                last_feedback = f"Safety boundary DENIED: {bridge_result.policy_decision.reason}"
                self._memory.record_strategy(
                    organization_id=objective.organization_id,
                    objective_id=objective.objective_id,
                    scenario_id=bridge_result.scenario.scenario_id
                    if bridge_result.scenario
                    else objective.objective_id,
                    fingerprint=fingerprint,
                    outcome=OUTCOME_DENIED,
                )
                self._novelty.register(fingerprint)
                self._state.transition(RedAgentState.DENIED)
                self._state.transition(RedAgentState.REFINE)
                self._state.transition(RedAgentState.ANALYZING)
                continue

            if bridge_result.policy_decision.status == PolicyDecisionStatus.ESCALATED:
                result.escalated = True
                result.final_state = RedAgentState.WAIT
                result.terminated_reason = "Human approval required; agent in WAIT."
                return result

            # ALLOWED
            self._state.transition(RedAgentState.ALLOWED)
            self._memory.record_strategy(
                organization_id=objective.organization_id,
                objective_id=objective.objective_id,
                scenario_id=bridge_result.scenario.scenario_id
                if bridge_result.scenario
                else objective.objective_id,
                fingerprint=fingerprint,
                outcome=OUTCOME_EXECUTED,
            )
            self._novelty.register(fingerprint)
            result.experiments += 1
            safety_rejections = 0  # consecutive-rejection counter resets on success
            result.executed_blueprints.extend(bridge_result.signed_blueprints)

            # EXECUTING / OBSERVING / EVALUATING / LEARNING
            outcome = self._execute_and_evaluate(
                result, objective, bridge_result, untrusted_telemetry
            )
            if outcome is not None:
                self._memory.update_outcome(
                    objective.organization_id, fingerprint.composite_hash, outcome
                )

            result.iterations += 1
            last_feedback = None
            self._state.transition(RedAgentState.EXECUTING)
            self._state.transition(RedAgentState.OBSERVING)
            self._state.transition(RedAgentState.EVALUATING)
            self._state.transition(RedAgentState.LEARNING)

            # CONTINUE or FINISHED based on budget / remaining iterations.
            if self._state.can_transition(RedAgentState.CONTINUE):
                self._state.transition(RedAgentState.CONTINUE)
            try:
                self._budget.assert_has_remaining(
                    result.iterations,
                    result.experiments,
                    result.llm_calls,
                    self._started_at,
                )
                self._state.transition(RedAgentState.ANALYZING)
            except BudgetExhaustedError as exc:
                self._state.transition(RedAgentState.FINISHED)
                result.final_state = RedAgentState.FINISHED
                result.terminated_reason = str(exc)
                return result

    # -- Internal helpers --------------------------------------------------
    def _obtain_decision(
        self,
        objective: SecurityObjective,
        result: RedAgentRunResult,
        untrusted_telemetry: Optional[list],
        prior_feedback: Optional[str],
    ) -> Optional[RedAgentDecision]:
        context = self._context_builder.build(
            objective,
            budget=self._budget.remaining(
                result.iterations,
                result.experiments,
                result.llm_calls,
                self._started_at,
            ),
        )
        user_prompt = build_user_prompt(
            context,
            untrusted_telemetry=untrusted_telemetry,
            prior_feedback=prior_feedback,
        )

        for _ in range(self.config.max_schema_retries):
            result.llm_calls += 1
            try:
                return self.config.provider.generate_structured(
                    prompt=user_prompt,
                    system_prompt=build_system_prompt(),
                    response_schema=RedAgentDecision,
                )
            except SchemaValidationError:
                continue
            except RedAgentException:
                return None
        return None

    def _execute_and_evaluate(
        self,
        result: RedAgentRunResult,
        objective: SecurityObjective,
        bridge_result: SafetyBridgeResult,
        untrusted_telemetry: Optional[list],
    ) -> Optional[str]:
        """Dispatch signed blueprints through the worker and evaluate detection.

        Returns a memory outcome string, or None when no worker/evaluator is
        configured (unit-test mode).
        """
        if not bridge_result.signed_blueprints:
            return None

        if self.config.worker is not None:
            executions = self._dispatch_to_worker(bridge_result)
            result.simulation_executions.extend(executions)
            for execution in executions:
                result.collected_telemetry.extend(
                    self._collect_telemetry(execution)
                )
            if executions and not any(
                getattr(e, "status", "") == "COMPLETED" for e in executions
            ):
                # Every blueprint was refused or failed at the worker boundary.
                if any(getattr(e, "status", "") == "REJECTED" for e in executions):
                    return OUTCOME_SIMULATION_REJECTED
                return OUTCOME_SIMULATION_FAILED

        # Detection evaluation: prefer explicit untrusted_telemetry, fall back
        # to worker-collected telemetry for end-to-end correlation.
        telemetry_events = None
        if untrusted_telemetry:
            from sentinelforge.detection.normalizer import TelemetryNormalizer
            normalizer = TelemetryNormalizer()
            telemetry_events = [
                ev for raw in untrusted_telemetry
                if (ev := normalizer.normalize(_as_json(raw))) is not None
            ]
        elif result.collected_telemetry:
            # Worker-collected NormalizedEvents are already normalized and
            # scoped to this execution. Clone them with cleared correlation_id
            # so the evaluator's scenario-isolation filter doesn't reject them
            # when comparing against the scenario_id. Original events retain
            # their blueprint_id correlation for evidence chain traceability.
            from sentinelforge.detection.normalizer import NormalizedEvent
            telemetry_events = []
            for ev in result.collected_telemetry:
                clone = NormalizedEvent(
                    event_id=ev.event_id,
                    correlation_id=None,
                    timestamp=ev.timestamp,
                    source=ev.source,
                    EventType=ev.EventType,
                    ProcessName=ev.ProcessName,
                    Executable=ev.Executable,
                    CommandLine=ev.CommandLine,
                    UserName=ev.UserName,
                    UserUid=ev.UserUid,
                    TargetFile=ev.TargetFile,
                    ContainerName=ev.ContainerName,
                    ContainerId=ev.ContainerId,
                    ParentProcess=ev.ParentProcess,
                    raw_event_hash=ev.raw_event_hash,
                )
                telemetry_events.append(clone)

        if (
            self.config.detection_evaluator is not None
            and self.config.sigma_engine is not None
            and bridge_result.scenario is not None
            and bridge_result.actions
        ):
            scenario_outcome = self.config.detection_evaluator.evaluate_scenario(
                scenario_id=bridge_result.scenario.scenario_id,
                actions=bridge_result.actions,
                events=telemetry_events or [],
                sigma_engine=self.config.sigma_engine,
                organization_id=objective.organization_id,
            )
            result.detection_outcome = scenario_outcome
            self._persist_detection_results(
                scenario_outcome, objective, bridge_result
            )
            self._persist_purple_evaluation(
                scenario_outcome, objective, bridge_result
            )
            return scenario_outcome.overall_outcome.value
        return OUTCOME_EXECUTED

    def _persist_detection_results(
        self,
        scenario_outcome: Any,
        objective: SecurityObjective,
        bridge_result: SafetyBridgeResult,
    ) -> None:
        """Persist ScenarioDetectionOutcome and per-rule DetectionResults to DB.

        Detection results are append-only evidence records. Persistence failures
        are logged and never raised (detection evaluation is not blocked by
        storage).
        """
        if self.config.db_session is None:
            return

        try:
            from sentinelforge.db.models import DetectionResult as DetectionResultRecord

            org_id = objective.organization_id
            now = datetime.now(timezone.utc)
            scenario_id_str = str(scenario_outcome.scenario_id)

            for action_outcome in scenario_outcome.action_outcomes:
                action_id_str = str(action_outcome.action_id)
                for rule_id in action_outcome.matched_rule_ids:
                    record = DetectionResultRecord(
                        id=uuid4(),
                        detection_id=uuid4(),
                        correlation_id=UUID(scenario_id_str) if scenario_id_str else None,
                        simulation_id=None,
                        action_id=UUID(action_id_str) if action_id_str else None,
                        exercise_id=None,
                        technique_id=action_outcome.technique_id,
                        rule_id=rule_id,
                        matched=True,
                        outcome="DETECTED",
                        timestamp=now,
                        source="sigma",
                    )
                    self.config.db_session.add(record)

            self.config.db_session.commit()
        except Exception as exc:
            logger.warning("Failed to persist detection results: %s", exc)
            try:
                self.config.db_session.rollback()
            except Exception as rollback_exc:
                logger.error(
                    "Detection results DB rollback also failed (original: %s): %s",
                    exc, rollback_exc,
                )

    def _persist_purple_evaluation(
        self,
        scenario_outcome: Any,
        objective: SecurityObjective,
        bridge_result: SafetyBridgeResult,
    ) -> None:
        """Persist a single PurpleEvaluation record for this experiment/scenario.

        One PurpleEvaluation per experiment — never per action.
        Persistence failures are logged and never raised.
        """
        if self.config.db_session is None:
            return

        try:
            from sentinelforge.detection.evaluator import PurpleEvaluator
            from sentinelforge.db.models import PurpleEvaluationRecord
            import json as json_lib

            purple_evaluator = PurpleEvaluator()

            execution_id = ""
            if bridge_result.signed_blueprints:
                execution_id = str(bridge_result.signed_blueprints[0].blueprint_id)

            purple_eval = purple_evaluator.evaluate(
                scenario_outcome=scenario_outcome,
                actions=bridge_result.actions or [],
                execution_id=execution_id,
                expected_detection=False,
            )

            org_uuid = UUID(str(objective.organization_id)) if objective.organization_id else UUID(int=0)
            exp_uuid = UUID(purple_eval.experiment_id) if purple_eval.experiment_id else None
            exec_uuid = UUID(purple_eval.execution_id) if purple_eval.execution_id else None

            record = PurpleEvaluationRecord(
                id=UUID(purple_eval.evaluation_id),
                organization_id=org_uuid,
                experiment_id=exp_uuid,
                execution_id=exec_uuid,
                technique_id=purple_eval.technique_id,
                detection_status=purple_eval.detection_status,
                matched_rule_ids=json_lib.dumps(purple_eval.matched_rule_ids),
                evidence_event_ids=json_lib.dumps(purple_eval.evidence_event_ids),
                expected_detection=purple_eval.expected_detection,
                gap_reason=purple_eval.gap_reason,
                detection_latency_ms=int(purple_eval.detection_latency_ms) if purple_eval.detection_latency_ms is not None else None,
                evaluated_at=datetime.now(timezone.utc),
            )
            self.config.db_session.add(record)
            self.config.db_session.commit()
        except Exception as exc:
            logger.warning("Failed to persist purple evaluation: %s", exc)
            try:
                self.config.db_session.rollback()
            except Exception as rollback_exc:
                logger.error(
                    "Purple evaluation DB rollback also failed (original: %s): %s",
                    exc, rollback_exc,
                )

    def _collect_telemetry(self, execution: Any) -> List[Any]:
        """Collect telemetry for one simulation execution (Step 2B).

        Eligibility is strict: telemetry is only claimed for executions that
        actually reached execution (COMPLETED/TIMEOUT). REJECTED and FAILED
        dispatches — denied, schema-invalid, unauthorized, invalid-signature,
        expired, replayed, policy-denied, or failed-before-execution — never
        produce telemetry.

        The existing TelemetryCollector does the normalization and Redis
        transport; the agent never interprets telemetry as instructions.
        """
        if self.config.telemetry_collector is None:
            return []
        if getattr(execution, "status", "") not in EXECUTED_SIMULATION_STATUSES:
            return []
        if self.config.telemetry_source is None:
            return []

        raw_lines = self.config.telemetry_source(execution) or []
        correlation_id = self._correlation_id_for(execution)
        events: List[Any] = []
        for raw in raw_lines:
            event = self.config.telemetry_collector.collect(
                raw, correlation_id=correlation_id
            )
            if event is not None:
                events.append(event)
        return events

    @staticmethod
    def _correlation_id_for(execution: Any) -> Optional[str]:
        """Deterministic correlation identifier for an execution.

        Derived solely from the executed blueprint identity (execution time
        window + container identity + command markers are the telemetry
        source's responsibility). Deterministic: the same blueprint always maps
        to the same correlation id. If no identity is available, correlation is
        NOT guessed and None (NULL) is returned.
        """
        blueprint_id = getattr(execution, "blueprint_id", None)
        return str(blueprint_id) if blueprint_id is not None else None

    def _dispatch_to_worker(self, bridge_result: SafetyBridgeResult) -> List[Any]:
        """Dispatch each signed blueprint to the existing SimulationWorker.

        This is the ONLY execution path: the agent never runs commands itself.
        Returns the SimulationExecution objects produced by the worker. A worker
        that raises (infrastructure/target failure) is recorded as a FAILED
        execution rather than crashing the loop (design section 19).
        """
        from sentinelforge.domain.simulation import SimulationExecution, SimulationRequest

        executions: List[Any] = []
        for blueprint in bridge_result.signed_blueprints:
            request = SimulationRequest(blueprint=blueprint)
            try:
                executions.append(self.config.worker.process(request))
            except Exception as exc:
                executions.append(
                    SimulationExecution(
                        simulation_id=uuid4(),
                        blueprint_id=blueprint.blueprint_id,
                        status="FAILED",
                        failure_reason=str(exc),
                    )
                )
        return executions


def _as_json(value: Any) -> str:
    """Coerce a telemetry record to a JSON string for normalization."""
    import json

    if isinstance(value, str):
        return value
    return json.dumps(value, default=str)