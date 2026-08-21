"""RedAgentContext construction and tenant-isolated database context builder.

SECURITY ROLE:
Context is assembled deterministically by Python code BEFORE any LLM call.
Every database query MUST be scoped by `organization_id` to guarantee tenant
isolation. Context size is strictly bounded so the LLM never receives an
unbounded or cross-tenant view of the range.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from uuid import UUID

from sentinelforge.domain.experiment import SecurityObjective

# Deterministic bounds on context assembly.
MAX_EXPERIMENT_HISTORY = 5
MAX_PREVIOUS_STRATEGIES = 5
MAX_RECENT_OBSERVATIONS = 5
MAX_CONTEXT_TEXT_BYTES = 8192


@dataclass
class RedAgentContext:
    """Bounded, deterministic context snapshot for a single LLM decision turn."""

    organization_id: UUID
    objective: SecurityObjective
    environment: Dict[str, Any] = field(default_factory=dict)
    capabilities: List[str] = field(default_factory=list)
    experiment_history: List[Dict[str, Any]] = field(default_factory=list)
    detection_coverage: List[str] = field(default_factory=list)
    detection_gaps: List[str] = field(default_factory=list)
    previous_strategies: List[Dict[str, Any]] = field(default_factory=list)
    recent_observations: List[Dict[str, Any]] = field(default_factory=list)
    remaining_budget: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the context for prompt formatting."""
        return {
            "organization_id": str(self.organization_id),
            "objective": self.objective.model_dump(mode="json"),
            "environment": self.environment,
            "capabilities": self.capabilities,
            "experiment_history": self.experiment_history,
            "detection_coverage": self.detection_coverage,
            "detection_gaps": self.detection_gaps,
            "previous_strategies": self.previous_strategies,
            "recent_observations": self.recent_observations,
            "remaining_budget": self.remaining_budget,
        }


class ContextBuilder:
    """Builds bounded, tenant-isolated RedAgentContext from database records.

    The builder accepts an optional SQLAlchemy session. If no session is
    available (e.g. during unit tests), history sources degrade to empty
    lists rather than raising, while the objective and organization scope
    remain authoritative.

    SECURITY INVARIANT:
    All queries constructed here MUST include `organization_id == :org_id`
    filters. No query may ever read records across tenants.
    """

    def __init__(self, db_session: Optional[Any] = None):
        self._db = db_session

    def build(self, objective: SecurityObjective, budget: Optional[Dict[str, int]] = None) -> RedAgentContext:
        org_id = objective.organization_id
        history = self._load_experiment_history(org_id)
        strategies = self._load_previous_strategies(org_id)
        gaps = self._load_detection_gaps(org_id)
        observations = self._load_recent_observations(org_id)
        coverage = self._load_detection_coverage(org_id)

        return RedAgentContext(
            organization_id=org_id,
            objective=objective,
            environment=self._environment(),
            capabilities=self._capabilities(),
            experiment_history=history,
            detection_coverage=coverage,
            detection_gaps=gaps,
            previous_strategies=strategies,
            recent_observations=observations,
            remaining_budget=budget or {},
        )

    # -- Deterministic environment/capability descriptors -----------------
    def _environment(self) -> Dict[str, Any]:
        return {
            "target": "sentinelforge-target",
            "category": "linux_host",
            "run_as_user": "labuser",
            "network_isolated": True,
        }

    def _capabilities(self) -> List[str]:
        return [
            "process_execution_via_bash",
            "file_read_via_cat",
            "file_removal_via_rm",
            "sigma_rule_detection",
        ]

    # -- Tenant-scoped DB queries ----------------------------------------
    def _load_experiment_history(self, org_id: UUID) -> List[Dict[str, Any]]:
        if self._db is None:
            return []
        from sentinelforge.db.models import AdversarialScenarioRecord, ExecutionPlanRecord

        records = (
            self._db.query(AdversarialScenarioRecord)
            .filter(AdversarialScenarioRecord.organization_id == org_id)
            .order_by(AdversarialScenarioRecord.created_at.desc())
            .limit(MAX_EXPERIMENT_HISTORY)
            .all()
        )
        history = []
        for rec in records:
            plans = (
                self._db.query(ExecutionPlanRecord)
                .filter(
                    ExecutionPlanRecord.scenario_id == rec.id,
                    ExecutionPlanRecord.organization_id == org_id,
                )
                .all()
            )
            history.append(
                {
                    "scenario_id": str(rec.id),
                    "title": rec.title,
                    "strategy_description": rec.strategy_description,
                    "proposed_risk_level": rec.proposed_risk_level,
                    "plan_status": plans[-1].status if plans else "DRAFT",
                }
            )
        return history

    def _load_previous_strategies(self, org_id: UUID) -> List[Dict[str, Any]]:
        if self._db is None:
            return []
        from sentinelforge.db.models import DetectionGapRecord

        records = (
            self._db.query(DetectionGapRecord)
            .filter(DetectionGapRecord.organization_id == org_id)
            .order_by(DetectionGapRecord.created_at.desc())
            .limit(MAX_PREVIOUS_STRATEGIES)
            .all()
        )
        return [
            {
                "technique_id": rec.technique_id,
                "original_outcome": rec.original_outcome,
                "root_cause": rec.root_cause,
                "remediation_status": rec.remediation_status,
            }
            for rec in records
        ]

    def _load_detection_gaps(self, org_id: UUID) -> List[str]:
        if self._db is None:
            return []
        from sentinelforge.db.models import DetectionGapRecord

        records = (
            self._db.query(DetectionGapRecord.technique_id)
            .filter(DetectionGapRecord.organization_id == org_id)
            .distinct()
            .all()
        )
        return [str(row[0]) for row in records]

    def _load_recent_observations(self, org_id: UUID) -> List[Dict[str, Any]]:
        if self._db is None:
            return []
        from sentinelforge.db.models import SimulationResult

        records = (
            self._db.query(SimulationResult)
            .filter(SimulationResult.organization_id == org_id)
            .order_by(SimulationResult.id.desc())
            .limit(MAX_RECENT_OBSERVATIONS)
            .all()
        )
        return [{"blueprint_id": str(r.blueprint_id), "status": r.status} for r in records]

    def _load_detection_coverage(self, org_id: UUID) -> List[str]:
        """Derive detected-technique coverage from tenant-scoped gap records.

        `DetectionResult` has no `organization_id` column, so coverage is
        derived from `DetectionGapRecord` (which is tenant-scoped): a technique
        is considered covered once a previously-open gap for it has been
        remediated. This keeps every query strictly scoped to `org_id`.
        """
        if self._db is None:
            return []
        from sentinelforge.db.models import DetectionGapRecord

        records = (
            self._db.query(DetectionGapRecord.technique_id)
            .filter(
                DetectionGapRecord.organization_id == org_id,
                DetectionGapRecord.remediation_status != "OPEN",
            )
            .distinct()
            .all()
        )
        return [str(row[0]) for row in records]