"""API request/response schemas for SentinelForge."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------
class DashboardMetrics(BaseModel):
    total_objectives: int = 0
    total_experiments: int = 0
    active_experiments: int = 0
    completed_experiments: int = 0
    total_detections: int = 0
    detection_gaps: int = 0
    coverage_pct: float = 0.0
    total_retests: int = 0
    retests_improved: int = 0
    system_status: str = "operational"
    recent_activities: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Objectives
# ---------------------------------------------------------------------------
class ObjectiveCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=512)
    description: str = Field(default="", max_length=4096)
    target_category: str = Field(default="linux_host", max_length=128)
    default_risk_level: str = Field(default="MEDIUM", pattern=r"^(LOW|MEDIUM|HIGH|CRITICAL)$")


class ObjectiveResponse(BaseModel):
    id: str
    organization_id: str
    title: str
    description: Optional[str] = None
    target_category: str
    default_risk_level: str
    created_at: str
    experiment_count: int = 0


class ObjectiveDetail(BaseModel):
    objective: ObjectiveResponse
    experiments: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Experiments
# ---------------------------------------------------------------------------
class ExperimentStartRequest(BaseModel):
    max_iterations: int = Field(default=3, ge=1, le=10)
    max_experiments: int = Field(default=2, ge=1, le=5)
    max_llm_calls: int = Field(default=15, ge=1, le=50)


class LifecycleStage(BaseModel):
    stage: str
    status: str  # pending, running, completed, failed, skipped
    label: str
    timestamp: Optional[str] = None
    result: Optional[str] = None
    detail: Optional[str] = None
    is_security_decision: bool = False  # True for deterministic, False for LLM proposal


class ExperimentResponse(BaseModel):
    id: str
    objective_id: str
    scenario_id: Optional[str] = None
    status: str
    title: Optional[str] = None
    strategy_description: Optional[str] = None
    technique_ids: List[str] = Field(default_factory=list)
    risk_level: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None
    iterations: int = 0
    experiments_count: int = 0
    llm_calls: int = 0
    terminated_reason: Optional[str] = None


class ExperimentDetail(BaseModel):
    experiment: ExperimentResponse
    lifecycle: List[LifecycleStage] = Field(default_factory=list)
    red_agent: Optional[Dict[str, Any]] = None
    telemetry: List[Dict[str, Any]] = Field(default_factory=list)
    detection: Optional[Dict[str, Any]] = None
    purple_evaluation: Optional[Dict[str, Any]] = None
    retest: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Telemetry
# ---------------------------------------------------------------------------
class TelemetryEvent(BaseModel):
    event_id: str
    correlation_id: Optional[str] = None
    timestamp: str
    source: str
    event_type: str
    process_name: str
    command_line: str
    user_name: str
    container_name: str
    technique_id: Optional[str] = None


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------
class DetectionResult(BaseModel):
    detection_id: str
    technique_id: str
    rule_id: str
    matched: bool
    outcome: str
    timestamp: str
    source: str


# ---------------------------------------------------------------------------
# Purple Evaluation
# ---------------------------------------------------------------------------
class PurpleEvaluationResponse(BaseModel):
    evaluation_id: str
    experiment_id: str
    execution_id: Optional[str] = None
    organization_id: str
    technique_id: str
    detection_status: str
    matched_rule_ids: List[str] = Field(default_factory=list)
    evidence_event_ids: List[str] = Field(default_factory=list)
    expected_detection: bool = False
    gap_reason: Optional[str] = None
    detection_latency_ms: Optional[float] = None
    evaluated_at: str


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------
class CoverageResponse(BaseModel):
    report_id: str
    organization_id: str
    total_experiments: int
    detected_experiments: int
    missed_experiments: int
    gap_experiments: int
    coverage_pct: float
    technique_coverage: Dict[str, bool] = Field(default_factory=dict)
    generated_at: str


# ---------------------------------------------------------------------------
# Retest
# ---------------------------------------------------------------------------
class RetestResponse(BaseModel):
    id: str
    organization_id: Optional[str] = None
    exercise_id: Optional[str] = None
    scenario_id: Optional[str] = None
    before_outcome: str
    after_outcome: str
    detection_improved: bool
    validated_rule_ids: List[str] = Field(default_factory=list)
    evaluated_at: str


# ---------------------------------------------------------------------------
# Evidence Trace
# ---------------------------------------------------------------------------
class EvidenceTrace(BaseModel):
    objective: Optional[Dict[str, Any]] = None
    experiment: Optional[Dict[str, Any]] = None
    execution: Optional[Dict[str, Any]] = None
    telemetry: List[Dict[str, Any]] = Field(default_factory=list)
    detection: Optional[Dict[str, Any]] = None
    purple_evaluation: Optional[Dict[str, Any]] = None
    retest: Optional[Dict[str, Any]] = None


# ---------------------------------------------------------------------------
# Health
# ---------------------------------------------------------------------------
class HealthResponse(BaseModel):
    status: str = "ok"
    version: str = "0.1.0"
    database: str = "connected"
    ollama: str = "unknown"
    docker: str = "unknown"


# ---------------------------------------------------------------------------
# Phase 11 — Cyber Immune API Schemas
# ---------------------------------------------------------------------------

class OrganizationCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=256)
    description: str = Field(default="", max_length=1024)


class OrganizationResponse(BaseModel):
    id: str
    name: str
    description: Optional[str] = None
    defensive_state: str = "INITIAL"
    created_at: Optional[str] = None


class OrganizationStateResponse(BaseModel):
    organization_id: str
    name: str
    experiments_performed: int = 0
    techniques_tested: List[str] = Field(default_factory=list)
    detected_experiments: int = 0
    missed_experiments: int = 0
    detection_gap_experiments: int = 0
    mitigated_gaps: int = 0
    unresolved_gaps: int = 0
    coverage_pct: float = 0.0
    defensive_improvements_attempted: int = 0
    successful_improvements: int = 0
    computed_at: str = ""


class ExperimentListResponse(BaseModel):
    id: str
    organization_id: str
    objective_id: Optional[str] = None
    title: Optional[str] = None
    strategy_description: Optional[str] = None
    risk_level: Optional[str] = None
    status: Optional[str] = None
    created_by: Optional[str] = None
    created_at: Optional[str] = None


class DetectionGapResponse(BaseModel):
    id: str
    organization_id: str
    scenario_id: Optional[str] = None
    technique_id: str
    original_outcome: str
    remediation_status: str = "OPEN"
    reason: str = ""
    created_at: Optional[str] = None


class DefensiveProposalResponse(BaseModel):
    id: str
    organization_id: str
    finding_id: Optional[str] = None
    scenario_id: Optional[str] = None
    root_cause: str = ""
    proposed_remediation: str = ""
    expected_security_effect: str = ""
    status: str = "CREATED"
    created_at: Optional[str] = None


class DefensiveProposalCreate(BaseModel):
    finding_id: str = Field(..., description="ID of the vulnerability finding")
    root_cause: str = Field(..., min_length=1, max_length=4096)
    proposed_remediation: str = Field(..., min_length=1, max_length=8192)
    expected_security_effect: str = Field(default="", max_length=4096)


class DefensiveProposalValidateResponse(BaseModel):
    proposal_id: str
    validation_passed: bool
    rejection_reason: Optional[str] = None
    status: str


class RetestListResponse(BaseModel):
    id: str
    organization_id: Optional[str] = None
    exercise_id: Optional[str] = None
    scenario_id: Optional[str] = None
    before_outcome: str = ""
    after_outcome: str = ""
    detection_improved: bool = False
    validated_rule_ids: List[str] = Field(default_factory=list)
    evaluated_at: Optional[str] = None


class ComparisonResponse(BaseModel):
    id: str
    organization_id: Optional[str] = None
    before_outcome: str = ""
    after_outcome: str = ""
    detection_improved: bool = False
    evaluated_at: Optional[str] = None


class ImmuneMemoryResponse(BaseModel):
    organization_id: str
    previous_experiments: int = 0
    techniques_tested: List[str] = Field(default_factory=list)
    detection_outcomes: Dict[str, int] = Field(default_factory=dict)
    detection_gaps: List[Dict[str, Any]] = Field(default_factory=list)
    retest_results: List[Dict[str, Any]] = Field(default_factory=list)
    coverage_pct: float = 0.0
    mitigated_gaps: int = 0
    unresolved_gaps: int = 0
    successful_improvements: int = 0
    failed_improvements: int = 0
    defensive_proposals: List[Dict[str, Any]] = Field(default_factory=list)


class NextExperimentResponse(BaseModel):
    organization_id: str
    selected_strategy: Optional[str] = None
    selected_techniques: List[str] = Field(default_factory=list)
    selection_method: str = "deterministic_fallback"
    score: float = 0.0
    reason: str = ""
    validation_passed: bool = False
    validation_rejection: Optional[str] = None
    used_llm: bool = False
    used_fallback: bool = False
    candidates_count: int = 0
    evidence_references: List[str] = Field(default_factory=list)
    selected_at: Optional[str] = None


class ImmuneCycleStatusResponse(BaseModel):
    organization_id: str
    current_state: str = "UNKNOWN"
    last_cycle_at: Optional[str] = None
    total_cycles: int = 0
    mitigated_count: int = 0
    unresolved_count: int = 0
    next_experiment: Optional[Dict[str, Any]] = None


class ImmuneCycleRunResponse(BaseModel):
    cycle_id: str
    organization_id: str
    final_state: str
    path: str = ""
    evidence: Dict[str, Any] = Field(default_factory=dict)
    next_experiment: Optional[Dict[str, Any]] = None


# ===========================================================================
# Digital Twin Schemas
# ===========================================================================

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


class DetectionCoverageCreate(BaseModel):
    """Request model for creating detection coverage record."""
    asset_id: Optional[str] = Field(None, description="ID of the asset")
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


class DigitalTwinSummaryResponse(BaseModel):
    """Comprehensive summary of an organization's Digital Twin."""
    organization_id: str
    organization_name: str
    total_assets: int = 0
    assets_by_type: Dict[str, int] = Field(default_factory=dict)
    total_services: int = 0
    services_by_type: Dict[str, int] = Field(default_factory=dict)
    internet_facing_services: int = 0
    total_controls: int = 0
    enabled_controls: int = 0
    controls_by_type: Dict[str, int] = Field(default_factory=dict)
    total_techniques_tested: int = 0
    techniques_detected: int = 0
    detection_coverage_pct: float = 0.0
    high_risk_assets: int = 0
    critical_risk_assets: int = 0
    unresolved_gaps: int = 0
    last_experiment_at: Optional[str] = None
    last_posture_snapshot_at: Optional[str] = None
    computed_at: str


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
