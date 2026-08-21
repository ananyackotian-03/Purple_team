"""SentinelForge Branch 2 — Domain Models for Application Vulnerability Remediation.

All models follow the Pydantic v2 pattern established in domain/experiment.py.
Every model carries organization_id for tenant isolation.
"""

from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class VulnerabilityCategory(str, Enum):
    INJECTION = "A03_INJECTION"
    BROKEN_AUTH = "A07_AUTH_FAILURES"
    SENSITIVE_DATA = "A02_CRYPTO_FAILURES"
    XXE = "A05_SECURITY_MISCONFIGURATION"
    BROKEN_ACCESS = "A01_BROKEN_ACCESS_CONTROL"
    SECURITY_MISCONFIG = "A05_SECURITY_MISCONFIGURATION"
    XSS = "A03_INJECTION"
    INSECURE_DESERIALIZATION = "A08_SOFTWARE_INTEGRITY"
    VULNERABLE_COMPONENTS = "A06_VULNERABLE_COMPONENTS"
    LOGGING_FAILURES = "09_LOGGER_FAILURES"
    SSRF = "A10_SSRF"
    OTHER = "OTHER"


class VulnerabilitySeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class VulnerabilityConfidence(str, Enum):
    CONFIRMED = "CONFIRMED"
    PROBABLE = "PROBABLE"
    SUSPECTED = "SUSPECTED"


class VulnerabilityStatus(str, Enum):
    OPEN = "OPEN"
    ROOT_CAUSE_IDENTIFIED = "ROOT_CAUSE_IDENTIFIED"
    REMEDIATION_PROPOSED = "REMEDIATION_PROPOSED"
    REMEDIATING = "REMEDIATING"
    REMEDIATION_VERIFIED = "REMEDIATION_VERIFIED"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    REQUIRES_HUMAN_REVIEW = "REQUIRES_HUMAN_REVIEW"
    ACCEPTED_RISK = "ACCEPTED_RISK"


class TargetType(str, Enum):
    LOCAL = "local"
    DOCKERIZED = "dockerized"
    REPOSITORY = "repository"


class TargetEnvironment(str, Enum):
    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    LAB = "lab"


class CloneStatus(str, Enum):
    CREATING = "CREATING"
    READY = "READY"
    REMEDIATING = "REMEDIATING"
    TESTING = "TESTING"
    ROLLING_BACK = "ROLLING_BACK"
    FAILED = "FAILED"
    CLEANED_UP = "CLEANED_UP"


class RemediationOutcome(str, Enum):
    VERIFIED = "VERIFIED"
    FAILED = "FAILED"
    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    REQUIRES_HUMAN_REVIEW = "REQUIRES_HUMAN_REVIEW"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"


# ---------------------------------------------------------------------------
# Domain Models
# ---------------------------------------------------------------------------

class VulnerabilityFinding(BaseModel):
    """A confirmed application vulnerability discovered by the Red Agent."""
    finding_id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    target_id: UUID
    exercise_id: Optional[UUID] = None
    scenario_id: Optional[UUID] = None
    attack_technique_id: str
    vulnerability_category: str
    affected_component: str
    evidence: str
    severity: VulnerabilitySeverity = VulnerabilitySeverity.MEDIUM
    confidence: VulnerabilityConfidence = VulnerabilityConfidence.SUSPECTED
    root_cause_hypothesis: Optional[str] = None
    reproduction_info: str
    status: VulnerabilityStatus = VulnerabilityStatus.OPEN
    remediation_status: str = "OPEN"
    iteration_count: int = 0
    max_iterations: int = 3
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    provenance: dict = Field(default_factory=dict)


class ApplicationTarget(BaseModel):
    """An authorized web application that SentinelForge may test."""
    target_id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    name: str
    description: str = ""
    target_type: TargetType = TargetType.DOCKERIZED
    environment: TargetEnvironment = TargetEnvironment.LAB
    repository_url: Optional[str] = None
    commit_sha: Optional[str] = None
    docker_image: Optional[str] = None
    docker_compose_path: Optional[str] = None
    local_path: Optional[str] = None
    owner_user_id: UUID = Field(default_factory=uuid4)
    authorized_by: UUID = Field(default_factory=uuid4)
    authorization_expiry: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc).replace(year=datetime.now(timezone.utc).year + 1)
    )
    allowed_technique_ids: List[str] = Field(default_factory=list)
    max_risk_level: str = "HIGH"
    network_isolated: bool = True
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class TargetClone(BaseModel):
    """An isolated copy of an ApplicationTarget used for remediation testing."""
    clone_id: UUID = Field(default_factory=uuid4)
    organization_id: UUID
    source_target_id: UUID
    source_revision: str
    clone_type: TargetType = TargetType.DOCKERIZED
    docker_container_name: Optional[str] = None
    docker_network: Optional[str] = None
    filesystem_path: Optional[str] = None
    network_isolated: bool = True
    max_cpu_seconds: int = 120
    max_memory_mb: int = 512
    max_disk_mb: int = 1024
    secrets_injected: List[str] = Field(default_factory=list)
    original_secrets_excluded: bool = True
    current_version: int = 1
    snapshot_ids: List[str] = Field(default_factory=list)
    status: CloneStatus = CloneStatus.CREATING
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc) + timedelta(minutes=30)
    )
    cleanup_status: str = "PENDING"


class PatchSpec(BaseModel):
    """A single file patch within a RemediationProposal."""
    file_path: str
    operation: str  # "modify", "create", "delete"
    original_content_hash: Optional[str] = None
    new_content_hash: Optional[str] = None
    patch_diff: str
    language: Optional[str] = None


class RemediationProposal(BaseModel):
    """Structured remediation proposal from the LLM. Never directly modifies files."""
    proposal_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    organization_id: UUID
    root_cause: str
    proposed_remediation: str
    affected_files: List[str] = Field(default_factory=list)
    patches: List[PatchSpec] = Field(default_factory=list)
    expected_security_effect: str
    expected_behavior: str
    test_plan: str
    rollback_plan: str
    risk_assessment: str
    schema_validated: bool = False
    policy_validated: bool = False
    clone_validated: bool = False
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    provenance: dict = Field(default_factory=dict)


class RemediationExecutionResult(BaseModel):
    """Result of applying a remediation proposal to a clone."""
    proposal_id: UUID
    clone_id: UUID
    snapshot_id: Optional[UUID] = None
    changes_applied: bool = False
    build_passed: bool = False
    tests_passed: bool = False
    behavior_preserved: bool = False
    build_output: str = ""
    test_output: str = ""


class CloneSnapshot(BaseModel):
    """A point-in-time snapshot of a clone for rollback."""
    snapshot_id: UUID = Field(default_factory=uuid4)
    clone_id: UUID
    version: int = 1
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    snapshot_type: str  # "pre_remediation", "post_remediation"
    file_hashes: Dict[str, str] = Field(default_factory=dict)
    container_snapshot_id: Optional[str] = None


class VulnerabilityRetestResult(BaseModel):
    """Result of Red Agent retesting a remediated vulnerability."""
    retest_id: UUID = Field(default_factory=uuid4)
    finding_id: UUID
    proposal_id: UUID
    clone_id: UUID
    attempt_number: int = 1
    original_attack_blocked: bool = False
    original_attack_evidence: str = ""
    variants_tested: int = 0
    variants_blocked: int = 0
    variant_details: List[dict] = Field(default_factory=list)
    regression_tests_passed: bool = False
    application_functional: bool = False
    vulnerability_eliminated: bool = False
    retest_outcome: str = "FAILED"  # VERIFIED, FAILED, REQUIRES_REVIEW
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    provenance: dict = Field(default_factory=dict)


class RemediationBudget(BaseModel):
    """Deterministic budget enforcement for remediation loops.

    The LLM cannot view or modify these limits.
    """
    max_iterations: int = Field(default=3, ge=1, le=100)
    max_llm_calls: int = Field(default=10, ge=1, le=1000)
    max_wall_time_seconds: int = Field(default=600, ge=1, le=86400)
    max_variants_per_retest: int = Field(default=3, ge=1, le=20)
    max_clone_lifetime_minutes: int = Field(default=30, ge=1, le=1440)

    def has_remaining(
        self,
        iteration: int,
        llm_calls: int,
        started_at: Optional[datetime] = None,
    ) -> bool:
        """Return True if budget has remaining capacity."""
        if iteration >= self.max_iterations:
            return False
        if llm_calls >= self.max_llm_calls:
            return False
        if started_at is not None:
            elapsed = (datetime.now(timezone.utc) - started_at).total_seconds()
            if elapsed >= self.max_wall_time_seconds:
                return False
        return True
