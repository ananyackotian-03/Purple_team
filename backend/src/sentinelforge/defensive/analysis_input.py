"""Structured input model for defensive analysis of a detection gap.

This model aggregates context from existing persisted records (DetectionGapRecord,
PurpleEvaluation, DetectionResult, etc.) to provide a defensive agent with the
information required to propose a defensive improvement.

The model is READ-ONLY — it never alters detection verdicts, ActionIR,
SignedBlueprint, PolicyEngine, or ExperimentSafetyBoundary state.

All data is derived from persistent evidence for tenant-isolated organizations.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import UUID

from pydantic import BaseModel, Field

from sentinelforge.domain.experiment import (
    RiskLevel,
    PolicyDecisionStatus,
    SecurityObjective,
)
from sentinelforge.detection.evaluator import (
    DetectionOutcome,
    ScenarioDetectionOutcome,
    ActionDetectionOutcome,
)
from sentinelforge.detection.sigma_engine import DetectionOutcome as SigmaOutcome


class DefensiveAnalysisInput(BaseModel):
    """Input model for defensive analysis of a detection gap.

    Aggregates context from existing persisted evidence records to enable
    deterministic defensive improvement proposals. The LLM receives this
    structured input and proposes a DEFENSIVE_PROPOSAL, which then passes
    through DefensiveSafetyBoundary validation before any state change.

    Fields are populated from existing DB records — never fabricated.
    """

    # Organization scoping
    organization_id: UUID = Field(
        description="Organization identifier for tenant isolation"
    )

    # Experiment identification
    experiment_id: UUID = Field(
        description="Adversarial scenario ID (the scenario that exposed the gap)"
    )
    execution_id: Optional[UUID] = Field(
        default=None,
        description="Signed blueprint/execution ID that was run",
    )

    # Technique identification
    technique_id: str = Field(
        description="MITRE ATT&CK technique ID that was not detected"
    )

    # Detection verdict context
    before_status: DetectionOutcome = Field(
        description="Detection status before any defensive improvement"
    )
    after_status: Optional[DetectionOutcome] = Field(
        default=None,
        description="Detection status after a previous defensive attempt (if any)",
    )

    # Gap metadata from DetectionGapRecord
    gap_reason: str = Field(
        description="Human-readable reason why this is a detection gap"
    )
    expected_detection: bool = Field(
        default=False,
        description="LLM metadata claim — does NOT influence detection_status",
    )
    gap_latency_ms: Optional[float] = Field(
        default=None,
        description="Detection latency from original execution",
    )

    # Evidence from the original evaluation
    matched_rule_ids: List[str] = Field(
        default_factory=list,
        description="Sigma rules that matched but didn't match the expected technique",
    )
    evidence_event_ids: List[str] = Field(
        default_factory=list,
        description="Normalized event IDs that were examined",
    )

    # Purple evaluation context
    purple_evaluation_id: Optional[str] = Field(
        default=None,
        description="Persistent PurpleEvaluation record ID",
    )
    purple_evaluation_technique: Optional[str] = Field(
        default=None,
        description="Technique ID from the PurpleEvaluation",
    )
    purple_detection_status: Optional[str] = Field(
        default=None,
        description="Detection status from the PurpleEvaluation",
    )

    # Telemetry / normalized event context
    telemetry_event_ids: List[str] = Field(
        default_factory=list,
        description="Normalized event IDs relevant to the action",
    )
    normalized_event_summary: str = Field(
        default="",
        description="Brief summary of telemetry observed for this action",
    )

    # Historical context — previously tested experiments for the same technique
    previous_experiments: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Previously run experiments testing the same technique",
    )

    # Retest context
    retest_id: Optional[str] = Field(
        default=None,
        description="Retest result ID if a retest has already been attempted",
    )
    retest_before: Optional[str] = Field(
        default=None,
        description="Before outcome from previous retest (NOT_DETECTED/DETECTED/DETECTION_GAP)",
    )
    retest_after: Optional[str] = Field(
        default=None,
        description="After outcome from previous retest",
    )
    retest_improved: Optional[bool] = Field(
        default=None,
        description="Whether the previous retest showed detection improvement",
    )

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
        }


class DefensiveAnalysisResult(BaseModel):
    """Result of running defensive analysis on the input.

    This is the structured output that the LLM uses to propose a defensive
    improvement. It documents the analysis reasoning without making claims
    about what the improvement should be — that is the LLM's role via the
    DEFENSIVE_PROPOSAL schema.

    The result must NOT be used to directly modify organizational state.
    """

    input: DefensiveAnalysisInput
    analysis_reasoning: str = Field(
        description="Deterministic summary of the gap context"
    )
    proposed_categories: List[str] = Field(
        default_factory=list,
        description="Allowed proposal categories for the LLM to choose from"
    )
    validation_requirements: List[str] = Field(
        default_factory=list,
        description="Mandatory validation checks the proposal must pass"
    )

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
        }