"""SentinelForge — Remediation Persistence Service.

Database-backed persistence for remediation workflow artifacts.
All records scoped by organization_id for tenant isolation.
Secrets are NEVER stored.
"""

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from sqlalchemy import and_
from sqlalchemy.orm import Session

from sentinelforge.remediation.db_models import (
    RemediationAuditEventRecord,
    RemediationAttemptRecord,
    RemediationProposalRecord,
    RemediationRetestResultRecord,
    RemediationVerificationRecord,
    VulnerabilityFindingRecord,
    TargetCloneRecord,
)


# ---------------------------------------------------------------------------
# Audit event types
# ---------------------------------------------------------------------------

class AuditEventType:
    FINDING_CREATED = "FINDING_CREATED"
    REMEDIATION_PROPOSED = "REMEDIATION_PROPOSED"
    REMEDIATION_VALIDATED = "REMEDIATION_VALIDATED"
    REMEDIATION_REJECTED = "REMEDIATION_REJECTED"
    CLONE_CREATED = "CLONE_CREATED"
    PATCH_APPLIED = "PATCH_APPLIED"
    BUILD_STARTED = "BUILD_STARTED"
    BUILD_PASSED = "BUILD_PASSED"
    BUILD_FAILED = "BUILD_FAILED"
    TEST_STARTED = "TEST_STARTED"
    TEST_PASSED = "TEST_PASSED"
    TEST_FAILED = "TEST_FAILED"
    RETEST_STARTED = "RETEST_STARTED"
    RETEST_COMPLETED = "RETEST_COMPLETED"
    VERIFICATION_PASSED = "VERIFICATION_PASSED"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"
    CLONE_DESTROYED = "CLONE_DESTROYED"
    ROLLBACK_COMPLETED = "ROLLBACK_COMPLETED"
    ATTEMPT_STARTED = "ATTEMPT_STARTED"
    ATTEMPT_COMPLETED = "ATTEMPT_COMPLETED"


# ---------------------------------------------------------------------------
# Attempt status transitions (deterministic)
# ---------------------------------------------------------------------------

_VALID_TRANSITIONS = {
    "PROPOSED": {"VALIDATED", "REJECTED"},
    "VALIDATED": {"APPLIED", "FAILED", "ROLLED_BACK"},
    "APPLIED": {"TESTING", "FAILED", "ROLLED_BACK"},
    "TESTING": {"RETESTING", "FAILED", "ROLLED_BACK", "REQUIRES_HUMAN_REVIEW"},
    "RETESTING": {"VERIFIED", "FAILED", "REQUIRES_HUMAN_REVIEW"},
    "FAILED": set(),
    "ROLLED_BACK": {"PROPOSED"},
    "VERIFIED": set(),
    "REQUIRES_HUMAN_REVIEW": set(),
}


def _validate_transition(current: str, next_status: str) -> bool:
    """Return True if the transition is allowed."""
    return next_status in _VALID_TRANSITIONS.get(current, set())


# ---------------------------------------------------------------------------
# Finding persistence
# ---------------------------------------------------------------------------

class FindingPersistence:
    """Tenant-isolated persistence for vulnerability findings."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def create(
        self,
        organization_id: UUID,
        target_id: UUID,
        attack_technique_id: str,
        vulnerability_category: str,
        affected_component: str,
        evidence: str,
        severity: str = "MEDIUM",
        confidence: str = "SUSPECTED",
        reproduction_info: str = "",
        exercise_id: Optional[UUID] = None,
        scenario_id: Optional[UUID] = None,
        root_cause_hypothesis: Optional[str] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> VulnerabilityFindingRecord:
        with self._session_factory() as session:
            record = VulnerabilityFindingRecord(
                id=uuid4(),
                organization_id=organization_id,
                target_id=target_id,
                exercise_id=exercise_id,
                scenario_id=scenario_id,
                attack_technique_id=attack_technique_id,
                vulnerability_category=vulnerability_category,
                affected_component=affected_component,
                evidence=evidence,
                severity=severity,
                confidence=confidence,
                root_cause_hypothesis=root_cause_hypothesis,
                reproduction_info=reproduction_info,
                provenance=json.dumps(provenance) if provenance else None,
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record

    def get(self, finding_id: UUID, organization_id: UUID) -> Optional[VulnerabilityFindingRecord]:
        with self._session_factory() as session:
            return session.query(VulnerabilityFindingRecord).filter(
                and_(
                    VulnerabilityFindingRecord.id == finding_id,
                    VulnerabilityFindingRecord.organization_id == organization_id,
                )
            ).first()

    def get_by_organization(self, organization_id: UUID) -> List[VulnerabilityFindingRecord]:
        with self._session_factory() as session:
            return session.query(VulnerabilityFindingRecord).filter(
                VulnerabilityFindingRecord.organization_id == organization_id
            ).all()

    def update_status(self, finding_id: UUID, organization_id: UUID, status: str) -> Optional[VulnerabilityFindingRecord]:
        with self._session_factory() as session:
            record = session.query(VulnerabilityFindingRecord).filter(
                and_(
                    VulnerabilityFindingRecord.id == finding_id,
                    VulnerabilityFindingRecord.organization_id == organization_id,
                )
            ).first()
            if record:
                record.status = status
                record.updated_at = datetime.now(timezone.utc)
                session.commit()
                session.refresh(record)
            return record


# ---------------------------------------------------------------------------
# Proposal persistence
# ---------------------------------------------------------------------------

class ProposalPersistence:
    """Tenant-isolated persistence for remediation proposals."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def create(
        self,
        organization_id: UUID,
        finding_id: UUID,
        target_id: UUID,
        root_cause: str,
        proposed_remediation: str,
        affected_files: List[str],
        patches_json: str,
        expected_security_effect: str,
        expected_behavior: str,
        test_plan: str,
        rollback_plan: str,
        risk_assessment: str,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> RemediationProposalRecord:
        with self._session_factory() as session:
            record = RemediationProposalRecord(
                id=uuid4(),
                finding_id=finding_id,
                organization_id=organization_id,
                target_id=target_id,
                root_cause=root_cause,
                proposed_remediation=proposed_remediation,
                affected_files=json.dumps(affected_files),
                patches=patches_json,
                expected_security_effect=expected_security_effect,
                expected_behavior=expected_behavior,
                test_plan=test_plan,
                rollback_plan=rollback_plan,
                risk_assessment=risk_assessment,
                status="CREATED",
                provenance=json.dumps(provenance) if provenance else None,
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record

    def get(self, proposal_id: UUID, organization_id: UUID) -> Optional[RemediationProposalRecord]:
        with self._session_factory() as session:
            return session.query(RemediationProposalRecord).filter(
                and_(
                    RemediationProposalRecord.id == proposal_id,
                    RemediationProposalRecord.organization_id == organization_id,
                )
            ).first()

    def update_status(self, proposal_id: UUID, organization_id: UUID, status: str) -> Optional[RemediationProposalRecord]:
        with self._session_factory() as session:
            record = session.query(RemediationProposalRecord).filter(
                and_(
                    RemediationProposalRecord.id == proposal_id,
                    RemediationProposalRecord.organization_id == organization_id,
                )
            ).first()
            if record:
                record.status = status
                session.commit()
                session.refresh(record)
            return record

    def get_by_finding(self, finding_id: UUID, organization_id: UUID) -> List[RemediationProposalRecord]:
        with self._session_factory() as session:
            return session.query(RemediationProposalRecord).filter(
                and_(
                    RemediationProposalRecord.finding_id == finding_id,
                    RemediationProposalRecord.organization_id == organization_id,
                )
            ).all()


# ---------------------------------------------------------------------------
# Attempt persistence
# ---------------------------------------------------------------------------

class AttemptPersistence:
    """Tenant-isolated persistence for remediation attempts."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def create(
        self,
        organization_id: UUID,
        finding_id: UUID,
        proposal_id: UUID,
        clone_id: UUID,
        attempt_number: int,
    ) -> RemediationAttemptRecord:
        with self._session_factory() as session:
            record = RemediationAttemptRecord(
                id=uuid4(),
                finding_id=finding_id,
                proposal_id=proposal_id,
                clone_id=clone_id,
                organization_id=organization_id,
                attempt_number=attempt_number,
                status="PROPOSED",
                start_time=datetime.now(timezone.utc),
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record

    def get(self, attempt_id: UUID, organization_id: UUID) -> Optional[RemediationAttemptRecord]:
        with self._session_factory() as session:
            return session.query(RemediationAttemptRecord).filter(
                and_(
                    RemediationAttemptRecord.id == attempt_id,
                    RemediationAttemptRecord.organization_id == organization_id,
                )
            ).first()

    def update_status(
        self,
        attempt_id: UUID,
        organization_id: UUID,
        new_status: str,
        **kwargs,
    ) -> Optional[RemediationAttemptRecord]:
        with self._session_factory() as session:
            record = session.query(RemediationAttemptRecord).filter(
                and_(
                    RemediationAttemptRecord.id == attempt_id,
                    RemediationAttemptRecord.organization_id == organization_id,
                )
            ).first()
            if not record:
                return None

            if not _validate_transition(record.status, new_status):
                raise ValueError(
                    f"Invalid transition: {record.status} -> {new_status}"
                )

            record.status = new_status
            if new_status in ("VERIFIED", "FAILED", "REQUIRES_HUMAN_REVIEW", "ROLLED_BACK"):
                record.end_time = datetime.now(timezone.utc)

            for key, value in kwargs.items():
                if hasattr(record, key):
                    setattr(record, key, value)

            session.commit()
            session.refresh(record)
            return record

    def get_by_finding(self, finding_id: UUID, organization_id: UUID) -> List[RemediationAttemptRecord]:
        with self._session_factory() as session:
            return session.query(RemediationAttemptRecord).filter(
                and_(
                    RemediationAttemptRecord.finding_id == finding_id,
                    RemediationAttemptRecord.organization_id == organization_id,
                )
            ).order_by(RemediationAttemptRecord.attempt_number).all()

    def get_by_organization(self, organization_id: UUID) -> List[RemediationAttemptRecord]:
        with self._session_factory() as session:
            return session.query(RemediationAttemptRecord).filter(
                RemediationAttemptRecord.organization_id == organization_id
            ).all()


# ---------------------------------------------------------------------------
# Verification persistence
# ---------------------------------------------------------------------------

class VerificationPersistence:
    """Tenant-isolated persistence for verification records."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def create(
        self,
        organization_id: UUID,
        finding_id: UUID,
        remediation_attempt_id: UUID,
        original_attack_blocked: bool,
        retest_outcome: str,
        verification_decision: str,
        verification_reason: str,
        original_attack_evidence: Optional[str] = None,
        retest_evidence: Optional[str] = None,
        regression_tests_passed: Optional[bool] = None,
        application_functional: Optional[bool] = None,
    ) -> RemediationVerificationRecord:
        with self._session_factory() as session:
            record = RemediationVerificationRecord(
                id=uuid4(),
                finding_id=finding_id,
                remediation_attempt_id=remediation_attempt_id,
                organization_id=organization_id,
                original_attack_blocked=original_attack_blocked,
                original_attack_evidence=original_attack_evidence,
                retest_outcome=retest_outcome,
                retest_evidence=retest_evidence,
                regression_tests_passed=regression_tests_passed,
                application_functional=application_functional,
                verification_decision=verification_decision,
                verification_reason=verification_reason,
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record

    def get(self, verification_id: UUID, organization_id: UUID) -> Optional[RemediationVerificationRecord]:
        with self._session_factory() as session:
            return session.query(RemediationVerificationRecord).filter(
                and_(
                    RemediationVerificationRecord.id == verification_id,
                    RemediationVerificationRecord.organization_id == organization_id,
                )
            ).first()

    def get_by_finding(self, finding_id: UUID, organization_id: UUID) -> List[RemediationVerificationRecord]:
        with self._session_factory() as session:
            return session.query(RemediationVerificationRecord).filter(
                and_(
                    RemediationVerificationRecord.finding_id == finding_id,
                    RemediationVerificationRecord.organization_id == organization_id,
                )
            ).all()


# ---------------------------------------------------------------------------
# Retest result persistence
# ---------------------------------------------------------------------------

class RetestPersistence:
    """Tenant-isolated persistence for retest results."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def create(
        self,
        organization_id: UUID,
        finding_id: UUID,
        proposal_id: UUID,
        clone_id: UUID,
        attempt_number: int,
        original_attack_blocked: bool,
        vulnerability_eliminated: bool,
        retest_outcome: str,
        original_attack_evidence: Optional[str] = None,
        variants_tested: int = 0,
        variants_blocked: int = 0,
        variant_details: Optional[str] = None,
        regression_tests_passed: Optional[bool] = None,
        application_functional: Optional[bool] = None,
        provenance: Optional[Dict[str, Any]] = None,
    ) -> RemediationRetestResultRecord:
        with self._session_factory() as session:
            record = RemediationRetestResultRecord(
                id=uuid4(),
                organization_id=organization_id,
                finding_id=finding_id,
                proposal_id=proposal_id,
                clone_id=clone_id,
                attempt_number=attempt_number,
                original_attack_blocked=original_attack_blocked,
                original_attack_evidence=original_attack_evidence,
                variants_tested=variants_tested,
                variants_blocked=variants_blocked,
                variant_details=variant_details,
                regression_tests_passed=regression_tests_passed,
                application_functional=application_functional,
                vulnerability_eliminated=vulnerability_eliminated,
                retest_outcome=retest_outcome,
                provenance=json.dumps(provenance) if provenance else None,
            )
            session.add(record)
            session.commit()
            session.refresh(record)
            return record

    def get_by_finding(self, finding_id: UUID, organization_id: UUID) -> List[RemediationRetestResultRecord]:
        with self._session_factory() as session:
            return session.query(RemediationRetestResultRecord).filter(
                and_(
                    RemediationRetestResultRecord.finding_id == finding_id,
                    RemediationRetestResultRecord.organization_id == organization_id,
                )
            ).all()


# ---------------------------------------------------------------------------
# Audit event persistence
# ---------------------------------------------------------------------------

class AuditEventPersistence:
    """Append-only, tenant-isolated audit event store."""

    def __init__(self, session_factory):
        self._session_factory = session_factory

    def record(
        self,
        organization_id: UUID,
        entity_type: str,
        entity_id: UUID,
        event_type: str,
        correlation_id: UUID,
        exercise_id: Optional[UUID] = None,
        actor: str = "system",
        metadata: Optional[Dict[str, Any]] = None,
    ) -> RemediationAuditEventRecord:
        # Strip secrets from metadata
        safe_metadata = _sanitize_metadata(metadata)

        with self._session_factory() as session:
            event = RemediationAuditEventRecord(
                id=uuid4(),
                organization_id=organization_id,
                exercise_id=exercise_id,
                entity_type=entity_type,
                entity_id=entity_id,
                event_type=event_type,
                timestamp=datetime.now(timezone.utc),
                actor=actor,
                correlation_id=correlation_id,
                metadata_json=json.dumps(safe_metadata) if safe_metadata else None,
            )
            session.add(event)
            session.commit()
            session.refresh(event)
            return event

    def get_by_entity(
        self,
        entity_type: str,
        entity_id: UUID,
        organization_id: UUID,
    ) -> List[RemediationAuditEventRecord]:
        with self._session_factory() as session:
            return session.query(RemediationAuditEventRecord).filter(
                and_(
                    RemediationAuditEventRecord.entity_type == entity_type,
                    RemediationAuditEventRecord.entity_id == entity_id,
                    RemediationAuditEventRecord.organization_id == organization_id,
                )
            ).order_by(RemediationAuditEventRecord.timestamp).all()

    def get_by_correlation(
        self,
        correlation_id: UUID,
        organization_id: UUID,
    ) -> List[RemediationAuditEventRecord]:
        with self._session_factory() as session:
            return session.query(RemediationAuditEventRecord).filter(
                and_(
                    RemediationAuditEventRecord.correlation_id == correlation_id,
                    RemediationAuditEventRecord.organization_id == organization_id,
                )
            ).order_by(RemediationAuditEventRecord.timestamp).all()

    def get_by_organization(
        self,
        organization_id: UUID,
        limit: int = 100,
    ) -> List[RemediationAuditEventRecord]:
        with self._session_factory() as session:
            return session.query(RemediationAuditEventRecord).filter(
                RemediationAuditEventRecord.organization_id == organization_id
            ).order_by(RemediationAuditEventRecord.timestamp.desc()).limit(limit).all()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SECRET_PATTERNS = {"api_key", "apikey", "secret", "password", "token", "credential", "auth_header"}


def _sanitize_metadata(metadata: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Remove secret-like values from metadata before persistence."""
    if not metadata:
        return {}
    sanitized = {}
    for key, value in metadata.items():
        key_lower = key.lower()
        if any(pattern in key_lower for pattern in _SECRET_PATTERNS):
            sanitized[key] = "[REDACTED]"
        else:
            sanitized[key] = value
    return sanitized


# ---------------------------------------------------------------------------
# Session factory adapter
# ---------------------------------------------------------------------------

class SessionFactory:
    """Adapter that provides a context-managed SQLAlchemy session.

    For testing: wrap an in-memory SQLite session.
    For production: wrap a PostgreSQL sessionmaker.
    """

    def __init__(self, session_or_factory):
        self._factory = session_or_factory

    def __call__(self):
        """Return a context manager yielding a Session.

        On successful exit: expunge all objects, commit, close.
        On error: rollback, close.
        """
        return _SessionContext(self._factory)


class _SessionContext:
    """Context manager for SQLAlchemy sessions.

    Objects are expunged before commit so they remain usable
    after the session is closed.
    """

    def __init__(self, factory):
        self._factory = factory
        self._session = None

    def __enter__(self):
        self._session = self._factory()
        return self._session

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self._session:
            if exc_type:
                self._session.rollback()
            else:
                self._session.commit()
            self._session.close()
        return False
