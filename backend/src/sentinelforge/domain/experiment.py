from datetime import datetime, timezone
from enum import Enum
from typing import List, Optional
from uuid import UUID, uuid4
from pydantic import BaseModel, Field
import yaml



class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PolicyDecisionStatus(str, Enum):
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    ESCALATED = "ESCALATED"


class SecurityObjective(BaseModel):
    objective_id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    title: str
    description: str
    target_category: str = "linux_host"
    default_risk_level: RiskLevel = RiskLevel.MEDIUM
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExperimentConstraints(BaseModel):
    allowed_targets: List[str] = Field(default_factory=lambda: ["sentinelforge-target"])
    allowed_users: List[str] = Field(default_factory=lambda: ["labuser"])
    max_execution_seconds: int = 30
    max_stdout_bytes: int = 64 * 1024
    network_isolated: bool = True
    max_risk_level: RiskLevel = RiskLevel.HIGH
    requires_human_approval: bool = False


class AdversarialScenario(BaseModel):
    scenario_id: UUID = Field(default_factory=uuid4)
    objective_id: UUID
    organization_id: UUID
    title: str
    strategy_description: str
    technique_ids: List[str]
    proposed_risk_level: RiskLevel = RiskLevel.MEDIUM
    created_by: str = "red_agent"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ExecutionPlan(BaseModel):
    plan_id: UUID = Field(default_factory=uuid4)
    scenario_id: UUID
    organization_id: UUID
    steps_description: str
    status: str = "DRAFT"  # DRAFT, APPROVED, REJECTED, EXECUTED
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PolicyDecision(BaseModel):
    decision_id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    scenario_id: Optional[UUID] = None
    blueprint_id: Optional[UUID] = None
    status: PolicyDecisionStatus
    reason: str
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ValidationSandboxStatus(str, Enum):
    ACCEPTED = "ACCEPTED"
    REJECTED = "REJECTED"


class CandidateSigmaRule(BaseModel):
    rule_id: str = Field(default_factory=lambda: str(uuid4()))
    title: str
    description: str
    technique_id: str
    logsource: dict = Field(default_factory=dict)
    detection: dict = Field(default_factory=dict)
    level: str = "medium"
    tags: List[str] = Field(default_factory=list)
    references: List[str] = Field(default_factory=list)
    source_scenario_id: str
    source_action_ids: List[str] = Field(default_factory=list)
    status: str = "CANDIDATE"  # CANDIDATE, VALIDATED, REJECTED
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def to_yaml(self) -> str:
        rule_dict = {
            "title": self.title,
            "id": self.rule_id,
            "status": self.status.lower(),
            "description": self.description,
            "references": self.references,
            "tags": self.tags,
            "logsource": self.logsource,
            "detection": self.detection,
            "level": self.level,
            "x-sentinelforge": {
                "scenario_id": str(self.source_scenario_id),
                "action_ids": [str(aid) for aid in self.source_action_ids],
                "technique_id": str(self.technique_id),
                "rule_id": str(self.rule_id),
            },
        }
        return yaml.dump(rule_dict, sort_keys=False)

    @classmethod
    def from_yaml(cls, rule_yaml: str) -> "CandidateSigmaRule":
        parsed = yaml.safe_load(rule_yaml) or {}
        meta = parsed.get("x-sentinelforge", {})
        return cls(
            rule_id=str(meta.get("rule_id", parsed.get("id", str(uuid4())))),
            title=str(parsed.get("title", "Untitled Candidate Rule")),
            description=str(parsed.get("description", "")),
            technique_id=str(meta.get("technique_id", "unknown")),
            logsource=parsed.get("logsource", {}),
            detection=parsed.get("detection", {}),
            level=str(parsed.get("level", "medium")),
            tags=parsed.get("tags", []),
            references=parsed.get("references", []),
            source_scenario_id=str(meta.get("scenario_id", "")),
            source_action_ids=[str(a) for a in meta.get("action_ids", [])],
            status=str(parsed.get("status", "CANDIDATE")).upper(),
        )


class ValidationSandboxResult(BaseModel):
    rule_id: str
    status: ValidationSandboxStatus
    malicious_passed: bool
    benign_passed: bool
    reason: str
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RetestRequest(BaseModel):
    retest_id: UUID = Field(default_factory=uuid4)
    scenario_id: UUID
    gap_action_ids: List[str]
    technique_ids: List[str]
    candidate_rules: List[CandidateSigmaRule]
    validation_result: ValidationSandboxResult
    retest_reason: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RetestResult(BaseModel):
    retest_id: UUID = Field(default_factory=uuid4)
    organization_id: Optional[UUID] = None
    exercise_id: Optional[UUID] = None
    scenario_id: UUID
    before_outcome: str  # DETECTION_GAP or NOT_DETECTED
    after_outcome: str   # DETECTED
    detection_improved: bool
    validated_rule_ids: List[str] = Field(default_factory=list)
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

