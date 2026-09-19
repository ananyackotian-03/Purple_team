"""Digital Twin Domain Models.

Pydantic models for Digital Twin API request/response schemas.
These models define the interface for interacting with the Digital Twin.

SECURITY INVARIANTS:
- All models require organization_id for tenant isolation
- No direct LLM mutation paths in request models
- State derivation is service-layer responsibility
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Asset Types
# ---------------------------------------------------------------------------
class AssetType(str):
    HOST = "host"
    CONTAINER = "container"
    SERVICE = "service"
    DATABASE = "database"
    NETWORK = "network"
    APPLICATION = "application"


class RiskLevel(str):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


# ---------------------------------------------------------------------------
# Asset Models
# ---------------------------------------------------------------------------
class AssetCreate(BaseModel):
    """Request model for creating a Digital Twin asset."""
    name: str = Field(..., min_length=1, max_length=256)
    asset_type: str = Field(..., description="host, container, service, database, network, application")
    description: str = Field(default="", max_length=4096)
    operating_system: Optional[str] = Field(None, max_length=128)
    software_version: Optional[str] = Field(None, max_length=128)
    network_segment: Optional[str] = Field(None, max_length=128)
    ip_address: Optional[str] = Field(None, max_length=45)
    risk_level: str = Field(default="MEDIUM", pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    tags: List[str] = Field(default_factory=list)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


class AssetResponse(BaseModel):
    """Response model for a Digital Twin asset."""
    id: str
    organization_id: str
    name: str
    asset_type: str
    description: Optional[str] = None
    operating_system: Optional[str] = None
    software_version: Optional[str] = None
    network_segment: Optional[str] = None
    ip_address: Optional[str] = None
    risk_level: str
    is_active: bool
    last_scanned_at: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class AssetListResponse(BaseModel):
    """Response model for listing Digital Twin assets."""
    assets: List[AssetResponse]
    total: int


# ---------------------------------------------------------------------------
# Service Models
# ---------------------------------------------------------------------------
class ServiceCreate(BaseModel):
    """Request model for creating a Digital Twin service."""
    asset_id: str = Field(..., description="ID of the parent asset")
    name: str = Field(..., min_length=1, max_length=256)
    service_type: str = Field(..., description="web_app, api, database, worker, cron, etc.")
    description: str = Field(default="", max_length=4096)
    port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[str] = Field(None, max_length=32)
    version: Optional[str] = Field(None, max_length=128)
    technology_stack: List[str] = Field(default_factory=list)
    risk_level: str = Field(default="MEDIUM", pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")
    is_internet_facing: bool = Field(default=False)
    has_authentication: bool = Field(default=True)
    has_encryption: bool = Field(default=True)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


class ServiceResponse(BaseModel):
    """Response model for a Digital Twin service."""
    id: str
    organization_id: str
    asset_id: str
    name: str
    service_type: str
    description: Optional[str] = None
    port: Optional[int] = None
    protocol: Optional[str] = None
    version: Optional[str] = None
    technology_stack: List[str] = Field(default_factory=list)
    risk_level: str
    is_internet_facing: bool
    has_authentication: bool
    has_encryption: bool
    last_tested_at: Optional[str] = None
    detection_rules_count: int
    coverage_pct: float
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class ServiceListResponse(BaseModel):
    """Response model for listing Digital Twin services."""
    services: List[ServiceResponse]
    total: int


# ---------------------------------------------------------------------------
# Security Control Models
# ---------------------------------------------------------------------------
class SecurityControlCreate(BaseModel):
    """Request model for creating a Digital Twin security control."""
    name: str = Field(..., min_length=1, max_length=256)
    control_type: str = Field(..., description="firewall, ids, siem, edr, waf, etc.")
    description: str = Field(default="", max_length=4096)
    enabled: bool = Field(default=True)
    version: Optional[str] = Field(None, max_length=128)
    vendor: Optional[str] = Field(None, max_length=256)
    technique_ids: List[str] = Field(default_factory=list)
    coverage_description: str = Field(default="", max_length=4096)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


class SecurityControlResponse(BaseModel):
    """Response model for a Digital Twin security control."""
    id: str
    organization_id: str
    name: str
    control_type: str
    description: Optional[str] = None
    enabled: bool
    version: Optional[str] = None
    vendor: Optional[str] = None
    technique_ids: List[str] = Field(default_factory=list)
    coverage_description: Optional[str] = None
    last_validated_at: Optional[str] = None
    validation_status: str
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class SecurityControlListResponse(BaseModel):
    """Response model for listing Digital Twin security controls."""
    controls: List[SecurityControlResponse]
    total: int


# ---------------------------------------------------------------------------
# Asset-Control Association Models
# ---------------------------------------------------------------------------
class AssetControlCreate(BaseModel):
    """Request model for associating a security control with an asset."""
    asset_id: str = Field(..., description="ID of the asset")
    control_id: str = Field(..., description="ID of the security control")
    applied_by: Optional[str] = Field(None, max_length=256)
    configuration_json: Dict[str, Any] = Field(default_factory=dict)


class AssetControlResponse(BaseModel):
    """Response model for an asset-control association."""
    id: str
    organization_id: str
    asset_id: str
    control_id: str
    applied_at: str
    applied_by: Optional[str] = None
    configuration_json: Dict[str, Any] = Field(default_factory=dict)
    last_tested_at: Optional[str] = None
    test_result: Optional[str] = None


# ---------------------------------------------------------------------------
# Service-Control Association Models
# ---------------------------------------------------------------------------
class ServiceControlCreate(BaseModel):
    """Request model for associating a security control with a service."""
    service_id: str = Field(..., description="ID of the service")
    control_id: str = Field(..., description="ID of the security control")
    protection_level: Optional[str] = Field(None, description="full, partial, monitoring")


class ServiceControlResponse(BaseModel):
    """Response model for a service-control association."""
    id: str
    organization_id: str
    service_id: str
    control_id: str
    applied_at: str
    protection_level: Optional[str] = None
    last_tested_at: Optional[str] = None
    test_result: Optional[str] = None


# ---------------------------------------------------------------------------
# Detection Coverage Models
# ---------------------------------------------------------------------------
class DetectionCoverageCreate(BaseModel):
    """Request model for creating detection coverage record."""
    asset_id: Optional[str] = Field(None, description="ID of the asset (or service_id)")
    service_id: Optional[str] = Field(None, description="ID of the service")
    technique_id: str = Field(..., min_length=1, max_length=32)
    is_detected: bool = Field(default=False)
    detection_method: Optional[str] = Field(None, max_length=128)
    rule_ids: List[str] = Field(default_factory=list)
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    metadata_json: Dict[str, Any] = Field(default_factory=dict)


class DetectionCoverageResponse(BaseModel):
    """Response model for detection coverage record."""
    id: str
    organization_id: str
    asset_id: Optional[str] = None
    service_id: Optional[str] = None
    technique_id: str
    is_detected: bool
    detection_method: Optional[str] = None
    rule_ids: List[str] = Field(default_factory=list)
    last_experiment_id: Optional[str] = None
    last_detected_at: Optional[str] = None
    confidence_score: float
    metadata_json: Dict[str, Any] = Field(default_factory=dict)
    created_at: str
    updated_at: str


class DetectionCoverageListResponse(BaseModel):
    """Response model for listing detection coverage records."""
    coverage: List[DetectionCoverageResponse]
    total: int
    detected_count: int
    not_detected_count: int
    overall_coverage_pct: float


# ---------------------------------------------------------------------------
# Security Posture Models
# ---------------------------------------------------------------------------
class SecurityPostureResponse(BaseModel):
    """Response model for security posture snapshot."""
    id: str
    organization_id: str
    total_assets: int
    active_assets: int
    total_services: int
    internet_facing_services: int
    total_security_controls: int
    enabled_controls: int
    total_techniques_tested: int
    techniques_detected: int
    detection_coverage_pct: float
    high_risk_assets: int
    critical_risk_assets: int
    unresolved_gaps: int
    total_experiments: int
    successful_experiments: int
    failed_experiments: int
    snapshot_date: str
    computed_from_evidence: bool


class SecurityPostureHistoryResponse(BaseModel):
    """Response model for security posture history."""
    snapshots: List[SecurityPostureResponse]
    total: int
    trend: str  # improving, degrading, stable


# ---------------------------------------------------------------------------
# Digital Twin Summary Models
# ---------------------------------------------------------------------------
class DigitalTwinSummaryResponse(BaseModel):
    """Comprehensive summary of an organization's Digital Twin."""
    organization_id: str
    organization_name: str
    
    # Asset summary
    total_assets: int = 0
    assets_by_type: Dict[str, int] = Field(default_factory=dict)
    
    # Service summary
    total_services: int = 0
    services_by_type: Dict[str, int] = Field(default_factory=dict)
    internet_facing_services: int = 0
    
    # Security control summary
    total_controls: int = 0
    enabled_controls: int = 0
    controls_by_type: Dict[str, int] = Field(default_factory=dict)
    
    # Coverage summary
    total_techniques_tested: int = 0
    techniques_detected: int = 0
    detection_coverage_pct: float = 0.0
    
    # Risk summary
    high_risk_assets: int = 0
    critical_risk_assets: int = 0
    unresolved_gaps: int = 0
    
    # Recent activity
    last_experiment_at: Optional[str] = None
    last_posture_snapshot_at: Optional[str] = None
    
    computed_at: str


# ---------------------------------------------------------------------------
# Relationship Models
# ---------------------------------------------------------------------------
class AssetWithRelationsResponse(BaseModel):
    """Asset with its associated services and controls."""
    asset: AssetResponse
    services: List[ServiceResponse] = Field(default_factory=list)
    controls: List[SecurityControlResponse] = Field(default_factory=list)


class ServiceWithRelationsResponse(BaseModel):
    """Service with its associated asset and controls."""
    service: ServiceResponse
    asset: AssetResponse
    controls: List[SecurityControlResponse] = Field(default_factory=list)
