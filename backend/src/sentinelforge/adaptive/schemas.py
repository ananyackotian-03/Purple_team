"""Phase 10 + Upgrade 6 — Adaptive Next-Experiment Selection schemas.

Structured Pydantic models for the selection pipeline. These schemas
are the authoritative contract between deterministic scoring, optional
LLM reasoning, and deterministic validation. They carry NO execution
authority of their own.

Upgrade 6 adds:
- DetectionGapProfile: deterministic per-technique gap model
- AdaptationMetrics: deterministic adaptation measurement
- Extended CandidateExperiment fields for adaptive scoring
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator

_TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d+)?$")


# ---------------------------------------------------------------------------
# Candidate experiment
# ---------------------------------------------------------------------------

class CandidateStatus(str, Enum):
    """Describes the testing history status of a technique."""
    NEVER_TESTED = "NEVER_TESTED"
    UNRESOLVED_GAP = "UNRESOLVED_GAP"
    MITIGATED_GAP = "MITIGATED_GAP"
    RECENTLY_DETECTED = "RECENTLY_DETECTED"
    PREVIOUSLY_FAILED_DEFENSE = "PREVIOUSLY_FAILED_DEFENSE"
    NOT_DETECTED = "NOT_DETECTED"
    RECENTLY_TESTED = "RECENTLY_TESTED"


class CandidateExperiment(BaseModel):
    """A candidate technique/strategy available for next-experiment selection.

    Populated deterministically from STRATEGY_CATALOG and ImmuneMemory.
    Upgrade 6 adds adaptive fields for evidence-based prioritization.
    """
    model_config = ConfigDict(extra="forbid")

    strategy_name: str = Field(..., max_length=128)
    technique_ids: List[str] = Field(..., min_length=1)
    title: str = Field(..., max_length=512)
    description: str = Field(..., max_length=4096)
    proposed_risk_level: str = Field(default="MEDIUM", max_length=16)
    candidate_status: CandidateStatus
    times_tested: int = Field(default=0, ge=0)
    times_detected: int = Field(default=0, ge=0)
    times_not_detected: int = Field(default=0, ge=0)
    has_unresolved_gap: bool = False
    defense_failed: bool = False
    last_tested_at: Optional[str] = None
    related_gap_ids: List[str] = Field(default_factory=list)

    # Upgrade 6 — Adaptive scoring fields
    detection_confidence: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Fraction of experiments where detection succeeded (0.0-1.0)",
    )
    attack_success_rate: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Fraction of experiments where attack succeeded (0.0-1.0)",
    )
    last_tested_days_ago: Optional[int] = Field(
        default=None, ge=0,
        description="Days since last test for this technique",
    )
    recent_experiment_count: int = Field(
        default=0, ge=0,
        description="Number of experiments in recent time window",
    )

    @field_validator("technique_ids")
    @classmethod
    def _valid_techniques(cls, v: List[str]) -> List[str]:
        cleaned = []
        for tech in v:
            tech = tech.strip()
            if not _TECHNIQUE_RE.match(tech):
                raise ValueError(f"invalid MITRE technique identifier: {tech!r}")
            cleaned.append(tech)
        return cleaned


# ---------------------------------------------------------------------------
# Security experience context
# ---------------------------------------------------------------------------

class SecurityExperienceContext(BaseModel):
    """Deterministic context summarizing organizational security history.

    Built from ImmuneMemory and OrganizationSecurityState. Contains NO
    LLM-generated content. Used by both the deterministic scorer and the
    LLM for informed experiment selection.
    """
    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(..., max_length=64)
    built_at: str = Field(..., max_length=64)

    # Organization security state
    total_experiments: int = Field(default=0, ge=0)
    coverage_pct: float = Field(default=0.0, ge=0.0, le=100.0)
    detected_experiments: int = Field(default=0, ge=0)
    missed_experiments: int = Field(default=0, ge=0)
    detection_gap_experiments: int = Field(default=0, ge=0)
    unresolved_gaps: int = Field(default=0, ge=0)
    mitigated_gaps: int = Field(default=0, ge=0)

    # Technique-level detail
    techniques_tested: List[str] = Field(default_factory=list)
    techniques_detected: List[str] = Field(default_factory=list)
    techniques_missed: List[str] = Field(default_factory=list)
    techniques_with_gap: List[str] = Field(default_factory=list)

    # Detection gap details
    detection_gaps: List[Dict[str, Any]] = Field(default_factory=list)

    # Retest history
    retest_results: List[Dict[str, Any]] = Field(default_factory=list)

    # Defensive improvement history
    successful_improvements: int = Field(default=0, ge=0)
    failed_improvements: int = Field(default=0, ge=0)
    defensive_proposals: List[Dict[str, Any]] = Field(default_factory=list)

    # Candidate experiments (from STRATEGY_CATALOG, filtered by history)
    candidates: List[CandidateExperiment] = Field(default_factory=list)

    # Upgrade 6 — Detection gap profiles (per-technique gap model)
    gap_profiles: List["DetectionGapProfile"] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------

class ScoredCandidate(BaseModel):
    """A candidate experiment with a deterministic priority score."""
    model_config = ConfigDict(extra="forbid")

    candidate: CandidateExperiment
    score: float = Field(default=0.0, ge=0.0)
    score_breakdown: Dict[str, float] = Field(default_factory=dict)
    explanation: str = Field(default="", max_length=2048)
    learning_value: float = Field(
        default=0.0, ge=0.0,
        description="Expected learning gain from this experiment (0.0-1.0)",
    )


# ---------------------------------------------------------------------------
# LLM proposal
# ---------------------------------------------------------------------------

class NextExperimentProposal(BaseModel):
    """Structured output from the LLM for next-experiment selection.

    The LLM must select from the provided candidate list and return a
    structured rationale. This proposal is then validated deterministically.
    """
    model_config = ConfigDict(extra="forbid")

    selected_strategy: str = Field(..., max_length=128)
    rationale: str = Field(..., max_length=4096)
    priority_reasons: List[str] = Field(default_factory=list, max_length=16)


# ---------------------------------------------------------------------------
# Selection result
# ---------------------------------------------------------------------------

class NextExperimentResult(BaseModel):
    """Final result of the next-experiment selection pipeline.

    Contains the selected experiment, scoring, validation status, and
    whether LLM or deterministic fallback was used.
    """
    model_config = ConfigDict(extra="forbid")

    organization_id: str = Field(..., max_length=64)
    selected_strategy: Optional[str] = None
    selected_techniques: List[str] = Field(default_factory=list)
    selection_method: str = Field(..., max_length=64)  # "llm" or "deterministic_fallback"
    score: float = Field(default=0.0, ge=0.0)
    reason: str = Field(default="", max_length=4096)
    validation_passed: bool = False
    validation_rejection: Optional[str] = None
    used_llm: bool = False
    used_fallback: bool = False
    candidates_count: int = Field(default=0, ge=0)
    evidence_references: List[str] = Field(default_factory=list)
    selected_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")


# ---------------------------------------------------------------------------
# Upgrade 6 — Detection gap profile
# ---------------------------------------------------------------------------

class DetectionGapProfile(BaseModel):
    """Deterministic per-technique detection gap model.

    Derived entirely from persisted PurpleEvaluation and DetectionGap records.
    No LLM input influences this model. Represents the organization's
    evidence-based understanding of detection capability per technique.
    """
    model_config = ConfigDict(extra="forbid")

    technique_id: str = Field(..., max_length=32)
    experiments_executed: int = Field(default=0, ge=0)
    attacks_detected: int = Field(default=0, ge=0)
    attacks_missed: int = Field(default=0, ge=0)
    detection_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    detection_confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    attack_success_rate: float = Field(default=0.0, ge=0.0, le=1.0)
    has_unresolved_gap: bool = False
    gap_count: int = Field(default=0, ge=0)
    last_tested: Optional[str] = None
    last_tested_days_ago: Optional[int] = Field(default=None, ge=0)
    priority: float = Field(default=0.0, ge=0.0)
    recent_experiment_count: int = Field(default=0, ge=0)


# ---------------------------------------------------------------------------
# Upgrade 6 — Adaptation metrics
# ---------------------------------------------------------------------------

class AdaptationMetrics(BaseModel):
    """Deterministic metrics measuring how SentinelForge adapts over time.

    All values are computed from persisted experiment history. No LLM
    input influences these metrics.
    """
    model_config = ConfigDict(extra="forbid")

    detection_coverage: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="detected_attacks / executed_attacks",
    )
    detection_gap: float = Field(
        default=1.0, ge=0.0, le=1.0,
        description="1.0 - detection_coverage (higher = worse)",
    )
    experiment_novelty: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="How different candidates are from recent experiments",
    )
    learning_gain: float = Field(
        default=0.0, ge=0.0,
        description="Observed increase in security knowledge from last experiment",
    )
    repetition_rate: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="Fraction of experiments that unnecessarily repeat recent tests",
    )
    adaptation_rate: float = Field(
        default=0.0, ge=0.0, le=1.0,
        description="How often candidate ranking changes as a consequence of experience",
    )
    total_experiments: int = Field(default=0, ge=0)
    techniques_with_gap: int = Field(default=0, ge=0)
    techniques_detected: int = Field(default=0, ge=0)
    techniques_tested: int = Field(default=0, ge=0)
    computed_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat() + "Z")
