from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
from enum import Enum
from datetime import datetime


class AssetType(str, Enum):
    HOST = "host"
    CONTAINER = "container"
    SERVICE = "service"
    DATABASE = "database"
    NETWORK = "network"
    APPLICATION = "application"


class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SecurityControl(BaseModel):
    """A security control associated with an organization."""
    control_id: str = Field(..., description="Unique control identifier")
    name: str = Field(..., description="Control name")
    description: str = Field(default="", description="Control description")
    technique_ids: List[str] = Field(
        default_factory=list, description="MITRE ATT&CK technique IDs covered")
    risk_level: RiskLevel = Field(default=RiskLevel.MEDIUM)
    enabled: bool = Field(default=True)
    last_validated: Optional[datetime] = Field(default=None)


class DetectionRule(BaseModel):
    """A detection rule associated with an organization."""
    rule_id: str = Field(..., description="Unique rule identifier")
    title: str = Field(..., description="Rule title")
    description: str = Field(default="", description="Rule description")
    technique_ids: List[str] = Field(
        default_factory=list, description="MITRE ATT&CK technique IDs")
    platform: str = Field(default="linux_host", description="Target platform")
    status: str = Field(default="active", description="Rule status")
    last_tested: Optional[datetime] = Field(default=None)
    times_triggered: int = Field(default=0)
    last_triggered: Optional[datetime] = Field(default=None)


class ExperimentSummary(BaseModel):
    """Summary of experiments run for an organization."""
    total_experiments: int = Field(default=0)
    detected: int = Field(default=0)
    missed: int = Field(default=0)
    gaps: int = Field(default=0)
    coverage_pct: float = Field(default=0.0)
    last_experiment_at: Optional[datetime] = Field(default=None)


class Organization(BaseModel):
    """Digital organization representation for SentinelForge Cyber Immune System.

    Represents a tenant organization with its assets, security controls,
    detection rules, and current defensive state. All data is derived from
    persisted evidence - never fabricated from LLM output.

    Tenant isolation is enforced by the organization_id field.
    """

    organization_id: UUID = Field(
        default_factory=uuid4, description="Unique organization identifier")
    name: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="", max_length=1024)

    # Assets managed by this organization
    assets: List[Dict[str, Any]] = Field(
        default_factory=list, description="Organization assets")

    # Security controls in force for this organization
    security_controls: List[SecurityControl] = Field(
        default_factory=list, description="Security controls")

    # Detection rules configured for this organization
    detection_rules: List[DetectionRule] = Field(
        default_factory=list, description="Detection rules")

    # Experiment history summary
    experiment_summary: ExperimentSummary = Field(
        default_factory=ExperimentSummary,
        description="Derived from persisted experiment/evaluation records")

    # Current defensive state summary
    defensive_state: str = Field(
        default="INITIAL",
        description="Current defensive posture state")

    created_at: datetime = Field(
        default_factory=datetime.now, description="Organization creation time")

    updated_at: datetime = Field(
        default_factory=datetime.now, description="Last update time")

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }


class OrganizationSummary(BaseModel):
    """Minimal organization info for list endpoints."""

    organization_id: str
    name: str
    defensive_state: str
    total_experiments: int = 0
    detected_experiments: int = 0
    coverage_pct: float = 0.0

    class Config:
        json_encoders = {
            datetime: lambda v: v.isoformat() if v else None
        }