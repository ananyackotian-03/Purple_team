"""Red Agent structured decision schemas (Pydantic v2).

SECURITY ROLE:
These schemas are the authoritative contract between the LLM (Tier 1,
untrusted reasoning) and the deterministic control plane (Tier 2).
Every field is type- and constraint-checked BEFORE any execution authority
is granted. Schemas carry NO execution authority of their own.
"""

import re
from datetime import datetime, timezone
from typing import List, Literal, Optional

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)

from sentinelforge.agents.red.exceptions import BudgetExhaustedError
from sentinelforge.domain.experiment import RiskLevel

# MITRE ATT&CK technique identifier, e.g. T1059 or T1059.004
_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d+)?$")

_MAX_EXECUTABLE_LEN = 128
_MAX_ARG_LEN = 256
_MAX_ARGS = 16
_MAX_TECHNIQUE_IDS = 16
_MAX_TEXT_LEN = 8192

_NOVELTY_CATEGORIES = {"NOVEL", "SIMILAR", "DUPLICATE"}


class ActionProposalSpec(BaseModel):
    """A single proposed action inside an adversarial scenario.

    This is a PROPOSAL only. It must pass ExperimentSafetyBoundary and
    PolicyEngine evaluation before it can be converted to an ActionIR.
    """

    model_config = ConfigDict(extra="forbid")

    target: str = Field(default="sentinelforge-target", max_length=128)
    run_as_user: str = Field(default="labuser", max_length=64)
    executable: str = Field(..., max_length=_MAX_EXECUTABLE_LEN)
    arguments: List[str] = Field(default_factory=list, max_length=_MAX_ARGS)
    technique_id: str = Field(..., max_length=32)

    @field_validator("executable", "target", "run_as_user")
    @classmethod
    def _no_control_chars(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("field must not be empty")
        if any(ord(ch) < 32 for ch in v):
            raise ValueError("control characters are not permitted")
        return v

    @field_validator("arguments")
    @classmethod
    def _sanitize_arguments(cls, v: List[str]) -> List[str]:
        cleaned = []
        for arg in v:
            if len(arg) > _MAX_ARG_LEN:
                raise ValueError(f"argument exceeds {_MAX_ARG_LEN} characters")
            if any(ord(ch) < 32 for ch in arg):
                raise ValueError("control characters are not permitted in arguments")
            cleaned.append(arg)
        return cleaned

    @field_validator("technique_id")
    @classmethod
    def _valid_technique(cls, v: str) -> str:
        if not _TECHNIQUE_RE.match(v.strip()):
            raise ValueError(f"invalid MITRE technique identifier: {v!r}")
        return v.strip()


class ScenarioProposalSpec(BaseModel):
    """A proposed AdversarialScenario with its constituent actions."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(..., max_length=512)
    strategy_description: str = Field(..., max_length=_MAX_TEXT_LEN)
    technique_ids: List[str] = Field(..., max_length=_MAX_TECHNIQUE_IDS)
    proposed_risk_level: RiskLevel = RiskLevel.MEDIUM
    proposed_actions: List[ActionProposalSpec] = Field(default_factory=list, max_length=8)

    @field_validator("title")
    @classmethod
    def _title_sane(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("title must not be empty")
        if any(ord(ch) < 32 for ch in v):
            raise ValueError("control characters are not permitted")
        return v

    @field_validator("technique_ids")
    @classmethod
    def _valid_techniques(cls, v: List[str]) -> List[str]:
        if not v:
            raise ValueError("at least one technique id is required")
        cleaned = []
        for tech in v:
            tech = tech.strip()
            if not _TECHNIQUE_RE.match(tech):
                raise ValueError(f"invalid MITRE technique identifier: {tech!r}")
            cleaned.append(tech)
        return cleaned


class ExpectedDetectionSpec(BaseModel):
    """The LLM's expectation of whether the range detections will fire."""

    model_config = ConfigDict(extra="forbid")

    should_detect: bool
    expected_rule_category: str = Field(..., max_length=256)
    reason: str = Field(..., max_length=_MAX_TEXT_LEN)

    @field_validator("expected_rule_category")
    @classmethod
    def _category_sane(cls, v: str) -> str:
        return v.replace("\x00", "").strip()


class NoveltyClaimSpec(BaseModel):
    """The LLM's self-claimed novelty category for a proposed scenario."""

    model_config = ConfigDict(extra="forbid")

    category: str = Field(..., max_length=64)
    differing_aspect: str = Field(..., max_length=_MAX_TEXT_LEN)

    @field_validator("category")
    @classmethod
    def _category_in_enum(cls, v: str) -> str:
        v = v.strip().upper()
        if v not in _NOVELTY_CATEGORIES:
            raise ValueError(f"category must be one of {sorted(_NOVELTY_CATEGORIES)}")
        return v


class RedAgentDecision(BaseModel):
    """Structured decision returned by the LLM.

    The `decision` discriminator is NOT an authorization. Regardless of what
    the LLM returns, execution only occurs after:
      1. Novelty evaluation (deterministic),
      2. ExperimentSafetyBoundary scenario + action evaluation,
      3. PolicyEngine allowlist validation,
      4. BlueprintSigner HMAC signature.
    """

    model_config = ConfigDict(extra="forbid")

    decision: Literal["PROPOSE_EXPERIMENT", "TERMINATE_OBJECTIVE"]
    hypothesis: str = Field(..., max_length=_MAX_TEXT_LEN)
    scenario: Optional[ScenarioProposalSpec] = None
    reasoning_summary: str = Field(..., max_length=_MAX_TEXT_LEN)
    expected_detection: Optional[ExpectedDetectionSpec] = None
    novelty_claim: Optional[NoveltyClaimSpec] = None

    @model_validator(mode="after")
    def _decision_consistency(self) -> "RedAgentDecision":
        if self.decision == "PROPOSE_EXPERIMENT" and self.scenario is None:
            raise ValueError("PROPOSE_EXPERIMENT requires a scenario proposal")
        return self


class RedAgentBudget(BaseModel):
    """Deterministic budget enforced by outer Python code.

    SECURITY ROLE:
    The LLM can never read or modify these counters. They are owned by the
    orchestrator loop; exceeding any limit raises BudgetExhaustedError.
    """

    model_config = ConfigDict(extra="forbid")

    max_iterations: int = Field(default=10, ge=1, le=10000)
    max_experiments: int = Field(default=8, ge=0, le=10000)
    max_llm_calls: int = Field(default=30, ge=1, le=100000)
    max_wall_time_seconds: int = Field(default=600, ge=1, le=86400)

    def remaining(
        self,
        iterations: int,
        experiments: int,
        llm_calls: int,
        started_at: Optional[datetime] = None,
    ) -> dict:
        """Return a snapshot of remaining budget as {field: remaining_int}."""
        remaining_wall = self.max_wall_time_seconds
        if started_at is not None:
            elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
            remaining_wall = max(0, int(self.max_wall_time_seconds - elapsed))
        return {
            "max_iterations": self.max_iterations - iterations,
            "max_experiments": self.max_experiments - experiments,
            "max_llm_calls": self.max_llm_calls - llm_calls,
            "max_wall_time_seconds": remaining_wall,
        }

    def assert_has_remaining(
        self,
        iterations: int,
        experiments: int,
        llm_calls: int,
        started_at: Optional[datetime] = None,
    ) -> None:
        """Raise BudgetExhaustedError if any budget limit has been reached.

        Raises:
            BudgetExhaustedError: When any configured limit is exceeded.
        """
        if iterations >= self.max_iterations:
            raise BudgetExhaustedError(
                f"iteration limit reached ({iterations}/{self.max_iterations})"
            )
        if experiments >= self.max_experiments:
            raise BudgetExhaustedError(
                f"experiment limit reached ({experiments}/{self.max_experiments})"
            )
        if llm_calls >= self.max_llm_calls:
            raise BudgetExhaustedError(
                f"LLM call limit reached ({llm_calls}/{self.max_llm_calls})"
            )
        if started_at is not None:
            elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
            if elapsed >= self.max_wall_time_seconds:
                raise BudgetExhaustedError(
                    f"wall-time limit reached ({int(elapsed)}/{self.max_wall_time_seconds}s)"
                )
