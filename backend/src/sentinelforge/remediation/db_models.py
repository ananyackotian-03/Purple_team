"""SentinelForge Branch 2 — Database Models for Application Vulnerability Remediation.

Appended AFTER existing Branch 1 tables. No modifications to existing tables.
All tables include organization_id for tenant isolation.
"""

from sqlalchemy import Column, String, DateTime, ForeignKey, Boolean, Integer, Text, Index
from sqlalchemy.dialects.postgresql import UUID
from datetime import datetime

from sentinelforge.db.models import Base


class ApplicationTargetRecord(Base):
    __tablename__ = 'application_targets'
    id = Column(UUID(as_uuid=True), primary_key=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    name = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    target_type = Column(String, nullable=False, default="dockerized")
    environment = Column(String, nullable=False, default="lab")
    repository_url = Column(String, nullable=True)
    commit_sha = Column(String, nullable=True)
    docker_image = Column(String, nullable=True)
    docker_compose_path = Column(String, nullable=True)
    local_path = Column(String, nullable=True)
    owner_user_id = Column(UUID(as_uuid=True), nullable=False)
    authorized_by = Column(UUID(as_uuid=True), nullable=False)
    authorization_expiry = Column(DateTime, nullable=False)
    allowed_technique_ids = Column(Text, nullable=True)
    max_risk_level = Column(String, nullable=False, default="HIGH")
    network_isolated = Column(Boolean, nullable=False, default=True)
    is_active = Column(Boolean, nullable=False, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)


class TargetCloneRecord(Base):
    __tablename__ = 'target_clones'
    id = Column(UUID(as_uuid=True), primary_key=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    source_target_id = Column(UUID(as_uuid=True), ForeignKey('application_targets.id'), nullable=False)
    source_revision = Column(String, nullable=False)
    clone_type = Column(String, nullable=False, default="dockerized")
    docker_container_name = Column(String, nullable=True)
    docker_network = Column(String, nullable=True)
    filesystem_path = Column(String, nullable=True)
    network_isolated = Column(Boolean, nullable=False, default=True)
    max_cpu_seconds = Column(Integer, nullable=False, default=120)
    max_memory_mb = Column(Integer, nullable=False, default=512)
    max_disk_mb = Column(Integer, nullable=False, default=1024)
    secrets_injected = Column(Text, nullable=True)
    original_secrets_excluded = Column(Boolean, nullable=False, default=True)
    current_version = Column(Integer, nullable=False, default=1)
    snapshot_ids = Column(Text, nullable=True)
    status = Column(String, nullable=False, default="CREATING")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    expires_at = Column(DateTime, nullable=True)
    cleanup_status = Column(String, nullable=False, default="PENDING")


class CloneSnapshotRecord(Base):
    __tablename__ = 'clone_snapshots'
    id = Column(UUID(as_uuid=True), primary_key=True)
    clone_id = Column(UUID(as_uuid=True), ForeignKey('target_clones.id'), nullable=False)
    version = Column(Integer, nullable=False, default=1)
    snapshot_type = Column(String, nullable=False)
    file_hashes = Column(Text, nullable=False, default="{}")
    container_snapshot_id = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class VulnerabilityFindingRecord(Base):
    __tablename__ = 'vulnerability_findings'
    id = Column(UUID(as_uuid=True), primary_key=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    target_id = Column(UUID(as_uuid=True), ForeignKey('application_targets.id'), nullable=False)
    exercise_id = Column(UUID(as_uuid=True), ForeignKey('exercises.id'), nullable=True)
    scenario_id = Column(UUID(as_uuid=True), nullable=True)
    attack_technique_id = Column(String, nullable=False)
    vulnerability_category = Column(String, nullable=False)
    affected_component = Column(String, nullable=False)
    evidence = Column(Text, nullable=False)
    severity = Column(String, nullable=False, default="MEDIUM")
    confidence = Column(String, nullable=False, default="SUSPECTED")
    root_cause_hypothesis = Column(Text, nullable=True)
    reproduction_info = Column(Text, nullable=False)
    status = Column(String, nullable=False, default="OPEN")
    remediation_status = Column(String, nullable=False, default="OPEN")
    iteration_count = Column(Integer, nullable=False, default=0)
    max_iterations = Column(Integer, nullable=False, default=3)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow)
    provenance = Column(Text, nullable=True)

    __table_args__ = (
        Index('ix_findings_org', 'organization_id'),
        Index('ix_findings_target', 'target_id'),
        Index('ix_findings_status', 'organization_id', 'status'),
    )


class RemediationProposalRecord(Base):
    __tablename__ = 'remediation_proposals'
    id = Column(UUID(as_uuid=True), primary_key=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey('vulnerability_findings.id'), nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    target_id = Column(UUID(as_uuid=True), ForeignKey('application_targets.id'), nullable=False)
    root_cause = Column(Text, nullable=False)
    proposed_remediation = Column(Text, nullable=False)
    affected_files = Column(Text, nullable=False, default="[]")
    patches = Column(Text, nullable=False, default="[]")
    expected_security_effect = Column(Text, nullable=False)
    expected_behavior = Column(Text, nullable=False)
    test_plan = Column(Text, nullable=False)
    rollback_plan = Column(Text, nullable=False)
    risk_assessment = Column(Text, nullable=False)
    status = Column(String, nullable=False, default="CREATED")
    schema_validated = Column(Boolean, nullable=False, default=False)
    policy_validated = Column(Boolean, nullable=False, default=False)
    clone_validated = Column(Boolean, nullable=False, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    provenance = Column(Text, nullable=True)

    __table_args__ = (
        Index('ix_proposals_org', 'organization_id'),
        Index('ix_proposals_finding', 'finding_id'),
    )


class RemediationAttemptRecord(Base):
    __tablename__ = 'remediation_attempts'
    id = Column(UUID(as_uuid=True), primary_key=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey('vulnerability_findings.id'), nullable=False)
    proposal_id = Column(UUID(as_uuid=True), ForeignKey('remediation_proposals.id'), nullable=False)
    clone_id = Column(UUID(as_uuid=True), ForeignKey('target_clones.id'), nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    snapshot_id = Column(UUID(as_uuid=True), nullable=True)
    attempt_number = Column(Integer, nullable=False)
    status = Column(String, nullable=False, default="PROPOSED")
    start_time = Column(DateTime, nullable=True)
    end_time = Column(DateTime, nullable=True)
    changes_applied = Column(Boolean, nullable=True)
    files_changed = Column(Text, nullable=True)
    build_passed = Column(Boolean, nullable=True)
    tests_passed = Column(Boolean, nullable=True)
    behavior_preserved = Column(Boolean, nullable=True)
    build_output = Column(Text, nullable=True)
    test_output = Column(Text, nullable=True)
    failure_reason = Column(Text, nullable=True)
    rollback_status = Column(String, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    provenance = Column(Text, nullable=True)

    __table_args__ = (
        Index('ix_attempts_org', 'organization_id'),
        Index('ix_attempts_finding', 'finding_id'),
        Index('ix_attempts_status', 'organization_id', 'status'),
    )


class RemediationVerificationRecord(Base):
    __tablename__ = 'remediation_verifications'
    id = Column(UUID(as_uuid=True), primary_key=True)
    finding_id = Column(UUID(as_uuid=True), ForeignKey('vulnerability_findings.id'), nullable=False)
    remediation_attempt_id = Column(UUID(as_uuid=True), ForeignKey('remediation_attempts.id'), nullable=False)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    original_attack_blocked = Column(Boolean, nullable=False)
    original_attack_evidence = Column(Text, nullable=True)
    retest_outcome = Column(String, nullable=False)
    retest_evidence = Column(Text, nullable=True)
    regression_tests_passed = Column(Boolean, nullable=True)
    application_functional = Column(Boolean, nullable=True)
    verification_decision = Column(String, nullable=False)
    verification_reason = Column(Text, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)

    __table_args__ = (
        Index('ix_verifications_org', 'organization_id'),
        Index('ix_verifications_finding', 'finding_id'),
    )


class RemediationRetestResultRecord(Base):
    __tablename__ = 'remediation_retest_results'
    id = Column(UUID(as_uuid=True), primary_key=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    finding_id = Column(UUID(as_uuid=True), ForeignKey('vulnerability_findings.id'), nullable=False)
    proposal_id = Column(UUID(as_uuid=True), ForeignKey('remediation_proposals.id'), nullable=False)
    clone_id = Column(UUID(as_uuid=True), ForeignKey('target_clones.id'), nullable=False)
    attempt_number = Column(Integer, nullable=False)
    original_attack_blocked = Column(Boolean, nullable=False)
    original_attack_evidence = Column(Text, nullable=True)
    variants_tested = Column(Integer, nullable=False, default=0)
    variants_blocked = Column(Integer, nullable=False, default=0)
    variant_details = Column(Text, nullable=True)
    regression_tests_passed = Column(Boolean, nullable=True)
    application_functional = Column(Boolean, nullable=True)
    vulnerability_eliminated = Column(Boolean, nullable=False)
    retest_outcome = Column(String, nullable=False)
    evaluated_at = Column(DateTime, default=datetime.utcnow)
    provenance = Column(Text, nullable=True)


class RemediationAuditEventRecord(Base):
    """Append-only audit trail for security-significant remediation actions."""
    __tablename__ = 'remediation_audit_events'
    id = Column(UUID(as_uuid=True), primary_key=True)
    organization_id = Column(UUID(as_uuid=True), ForeignKey('organizations.id'), nullable=False)
    exercise_id = Column(UUID(as_uuid=True), nullable=True)
    entity_type = Column(String, nullable=False)
    entity_id = Column(UUID(as_uuid=True), nullable=False)
    event_type = Column(String, nullable=False)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)
    actor = Column(String, nullable=False, default="system")
    correlation_id = Column(UUID(as_uuid=True), nullable=False)
    metadata_json = Column(Text, nullable=True)

    __table_args__ = (
        Index('ix_audit_org', 'organization_id'),
        Index('ix_audit_entity', 'entity_type', 'entity_id'),
        Index('ix_audit_correlation', 'correlation_id'),
        Index('ix_audit_timestamp', 'organization_id', 'timestamp'),
    )
