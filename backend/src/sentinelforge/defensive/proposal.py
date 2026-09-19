"""Defensive improvement proposal schema and persistence model.

The LLM generates a structured DefensiveProposal, which must then pass
through DefensiveSafetyBoundary validation before any organizational state
change. The LLM cannot persist a proposal as an approved defensive change
directly — persistent storage requires validation and authorization.

Proposal types are explicitly enumerated; the LLM may only propose from
the allowed set.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import UUID

from enum import Enum
from uuid import UUID, uuid4
from pydantic import BaseModel, Field, validator


# ---------------------------------------------------------------------------
# Allowed proposal types — explicitly enumerated. The LLM may ONLY propose
# from this set. Any other proposal_type is rejected by
# DefensiveSafetyBoundary.
# ---------------------------------------------------------------------------

class ProposalType(str, Enum):
    """Enumerated allowed defensive improvement proposal types."""

    ADD_DETECTION_RULE = "ADD_DETECTION_RULE"
    MODIFY_DETECTION_RULE = "MODIFY_DETECTION_RULE"
    IMPROVE_TELEMETRY = "IMPROVE_TELEMETRY"
    IMPROVE_CORRELATION = "IMPROVE_CORRELATION"
    MODIFY_SECURITY_CONTROL = "MODIFY_SECURITY_CONTROL"
    OTHER_ALLOWED_DEFENSIVE_CHANGE = "OTHER_ALLOWED_DEFENSIVE_CHANGE"

    @classmethod
    def allowed_values(cls) -> list[str]:
        """Return the list of allowed proposal type strings."""
        return [member.value for member in cls]


# ---------------------------------------------------------------------------
# DefensiveProposal schema
# ---------------------------------------------------------------------------


class DefensiveProposal(BaseModel):
    """Structured defensive improvement proposal from the LLM.

    The LLM may generate this proposal based on DefensiveAnalysisInput, but
    it must pass through DefensiveSafetyBoundary validation before any state
    change. The proposal is persisted ONLY after validation — the LLM cannot
    directly persist it as an approved change.

    Persisted records require: schema_validated=True, policy_validated=True,
    and authorization before any organizational state is modified.
    """

    proposal_id: UUID = Field(
        default_factory=uuid4,
        description="Unique proposal identifier",
    )
    organization_id: UUID = Field(
        description="Organization identifier for tenant isolation",
    )
    gap_id: UUID = Field(
        description="Detection gap ID that this proposal addresses",
    )
    experiment_id: UUID = Field(
        description="Adversarial scenario ID that exposed the gap",
    )
    technique_id: str = Field(
        description="MITRE ATT&CK technique ID affected by the proposal",
    )
    proposal_type: ProposalType = Field(
        description="Type of defensive improvement proposed — must be from "
        "the allowed enumeration",
    )
    description: str = Field(
        min_length=1,
        max_length=4096,
        description="Human-readable description of the proposed change",
    )
    rationale: str = Field(
        min_length=1,
        max_length=2048,
        description="LLM-generated rationale for why this improvement "
        "should detect the technique more effectively",
    )
    expected_effect: str = Field(
        min_length=1,
        max_length=512,
        description="Expected outcome if the proposal is implemented "
        "(e.g. 'Sigma rule will match T1003.008 log deletion events')",
    )
    validation_requirements: List[str] = Field(
        default_factory=list,
        description="Mandatory validation checks the proposal must pass "
        "(populated by DefensiveSafetyBoundary)",
    )
    status: str = Field(
        default="PROPOSED",
        description="Current proposal status — PROPOSED, VALIDATED, APPLIED, "
        "RETTESTING, RETESTED, MITIGATED, UNRESOLVED",
    )
    created_at: datetime = Field(
        default_factory=datetime.now,
        description="When the proposal was created",
    )
    validated_at: Optional[datetime] = Field(
        default=None,
        description="When the proposal passed safety/policy validation",
    )
    approved_at: Optional[datetime] = Field(
        default=None,
        description="When the proposal was approved for application",
    )
    rejected_reason: Optional[str] = Field(
        default=None,
        description="Why the proposal was rejected, if applicable",
    )

    # Persistence / audit fields
    persisted_at: Optional[datetime] = Field(
        default=None,
        description="When the proposal was persisted to the database",
    )
    provenance: str = Field(
        default="llm_generated",
        description="Source of the proposal — lm_generated, human_approved, etc.",
    )

    @validator("proposal_type")
    def validate_proposal_type(cls, v):
        """Ensure the proposal_type is from the allowed enumeration."""
        allowed = ProposalType.allowed_values()
        if v not in allowed:
            raise ValueError(
                f"Invalid proposal_type '{v}'. "
                f"Must be one of: {', '.join(allowed)}"
            )
        return v

    @validator("status")
    def validate_status(cls, v):
        """Ensure status is one of the allowed values."""
        allowed = [
            "PROPOSED",
            "VALIDATED",
            "APPLIED",
            "RETTESTING",
            "RETESTED",
            "MITIGATED",
            "UNRESOLVED",
        ]
        if v not in allowed:
            raise ValueError(
                f"Invalid status '{v}'. Must be one of: {', '.join(allowed)}"
            )
        return v

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None,
        }