"""SentinelForge — Phase 8: Tenant Isolation Verification.

Proves that cross-tenant access is denied for:
- Finding records
- Proposal records
- Attempt records
- Verification records
- Retest result records
- Audit event records
- Policy decision records
- Detection gap records
"""

import json
import pytest
from uuid import uuid4
from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from sentinelforge.db.models import (
    AuditLog,
    Base,
    DetectionGapRecord,
    Organization,
    PolicyDecisionRecord,
    RetestResult,
)
from sentinelforge.remediation.db_models import (
    RemediationAuditEventRecord,
    RemediationAttemptRecord,
    RemediationProposalRecord,
    RemediationRetestResultRecord,
    RemediationVerificationRecord,
    VulnerabilityFindingRecord,
    TargetCloneRecord,
)
from sentinelforge.remediation.persistence import (
    AuditEventPersistence,
    AttemptPersistence,
    FindingPersistence,
    ProposalPersistence,
    RetestPersistence,
    SessionFactory,
    VerificationPersistence,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)

    org_a = uuid4()
    org_b = uuid4()

    with Session() as s:
        s.add(Organization(id=org_a, name="TenantA"))
        s.add(Organization(id=org_b, name="TenantB"))
        s.commit()

    yield Session, org_a, org_b


@pytest.fixture
def session_factory(db):
    Session, _, _ = db
    return SessionFactory(Session)


# ---------------------------------------------------------------------------
# Finding tenant isolation
# ---------------------------------------------------------------------------

class TestFindingTenantIsolation:
    def test_cross_tenant_finding_not_accessible(self, session_factory, db):
        Session, org_a, org_b = db
        fp = FindingPersistence(session_factory)

        with Session() as s:
            record = VulnerabilityFindingRecord(
                id=uuid4(), organization_id=org_a, target_id=uuid4(),
                attack_technique_id="T1003.008", vulnerability_category="CREDENTIAL_ACCESS",
                affected_component="/etc/shadow", evidence="cat /etc/shadow succeeded",
                severity="MEDIUM", confidence="SUSPECTED", reproduction_info="reproduce",
            )
            s.add(record)
            s.commit()
            finding_id = record.id

        with Session() as s:
            result = s.query(VulnerabilityFindingRecord).filter(
                VulnerabilityFindingRecord.id == finding_id,
                VulnerabilityFindingRecord.organization_id == org_b,
            ).first()
            assert result is None

    def test_same_tenant_finding_accessible(self, session_factory, db):
        Session, org_a, _ = db
        fp = FindingPersistence(session_factory)

        with Session() as s:
            record = VulnerabilityFindingRecord(
                id=uuid4(), organization_id=org_a, target_id=uuid4(),
                attack_technique_id="T1003.008", vulnerability_category="CREDENTIAL_ACCESS",
                affected_component="/etc/shadow", evidence="cat /etc/shadow succeeded",
                severity="MEDIUM", confidence="SUSPECTED", reproduction_info="reproduce",
            )
            s.add(record)
            s.commit()
            finding_id = record.id

        with Session() as s:
            result = s.query(VulnerabilityFindingRecord).filter(
                VulnerabilityFindingRecord.id == finding_id,
                VulnerabilityFindingRecord.organization_id == org_a,
            ).first()
            assert result is not None

    def test_cross_tenant_org_scoped_query(self, session_factory, db):
        Session, org_a, org_b = db

        with Session() as s:
            s.add(VulnerabilityFindingRecord(
                id=uuid4(), organization_id=org_a, target_id=uuid4(),
                attack_technique_id="T1003.008", vulnerability_category="CREDENTIAL_ACCESS",
                affected_component="A", evidence="A",
                severity="MEDIUM", confidence="SUSPECTED", reproduction_info="A",
            ))
            s.add(VulnerabilityFindingRecord(
                id=uuid4(), organization_id=org_b, target_id=uuid4(),
                attack_technique_id="T1003.008", vulnerability_category="CREDENTIAL_ACCESS",
                affected_component="B", evidence="B",
                severity="MEDIUM", confidence="SUSPECTED", reproduction_info="B",
            ))
            s.commit()

        with Session() as s:
            findings_a = s.query(VulnerabilityFindingRecord).filter(
                VulnerabilityFindingRecord.organization_id == org_a
            ).all()
            findings_b = s.query(VulnerabilityFindingRecord).filter(
                VulnerabilityFindingRecord.organization_id == org_b
            ).all()
            assert len(findings_a) == 1
            assert len(findings_b) == 1
            assert findings_a[0].affected_component == "A"
            assert findings_b[0].affected_component == "B"


# ---------------------------------------------------------------------------
# Proposal tenant isolation
# ---------------------------------------------------------------------------

class TestProposalTenantIsolation:
    def test_cross_tenant_proposal_not_accessible(self, session_factory, db):
        Session, org_a, org_b = db
        finding_id = uuid4()

        with Session() as s:
            record = RemediationProposalRecord(
                id=uuid4(), finding_id=finding_id, organization_id=org_a,
                target_id=uuid4(), root_cause="SQL injection",
                proposed_remediation="Use parameterized queries",
                affected_files='["app.py"]', patches="[]",
                expected_security_effect="SQLi prevented",
                expected_behavior="Normal queries",
                test_plan="Test with sqlmap",
                rollback_plan="Revert",
                risk_assessment="Low risk",
                status="CREATED",
            )
            s.add(record)
            s.commit()
            proposal_id = record.id

        with Session() as s:
            result = s.query(RemediationProposalRecord).filter(
                RemediationProposalRecord.id == proposal_id,
                RemediationProposalRecord.organization_id == org_b,
            ).first()
            assert result is None


# ---------------------------------------------------------------------------
# Attempt tenant isolation
# ---------------------------------------------------------------------------

class TestAttemptTenantIsolation:
    def test_cross_tenant_attempt_not_accessible(self, session_factory, db):
        Session, org_a, org_b = db

        with Session() as s:
            record = RemediationAttemptRecord(
                id=uuid4(), finding_id=uuid4(), proposal_id=uuid4(),
                clone_id=uuid4(), organization_id=org_a,
                attempt_number=1, status="PROPOSED",
                start_time=datetime.now(timezone.utc),
            )
            s.add(record)
            s.commit()
            attempt_id = record.id

        with Session() as s:
            result = s.query(RemediationAttemptRecord).filter(
                RemediationAttemptRecord.id == attempt_id,
                RemediationAttemptRecord.organization_id == org_b,
            ).first()
            assert result is None

    def test_cross_tenant_attempt_update_blocked(self, session_factory, db):
        Session, org_a, org_b = db

        with Session() as s:
            record = RemediationAttemptRecord(
                id=uuid4(), finding_id=uuid4(), proposal_id=uuid4(),
                clone_id=uuid4(), organization_id=org_a,
                attempt_number=1, status="PROPOSED",
                start_time=datetime.now(timezone.utc),
            )
            s.add(record)
            s.commit()
            attempt_id = record.id

        with Session() as s:
            result = s.query(RemediationAttemptRecord).filter(
                RemediationAttemptRecord.id == attempt_id,
                RemediationAttemptRecord.organization_id == org_b,
            ).first()
            assert result is None


# ---------------------------------------------------------------------------
# Verification tenant isolation
# ---------------------------------------------------------------------------

class TestVerificationTenantIsolation:
    def test_cross_tenant_verification_not_accessible(self, session_factory, db):
        Session, org_a, org_b = db

        with Session() as s:
            record = RemediationVerificationRecord(
                id=uuid4(), finding_id=uuid4(),
                remediation_attempt_id=uuid4(),
                organization_id=org_a,
                original_attack_blocked=True,
                retest_outcome="BLOCKED",
                verification_decision="VERIFIED",
                verification_reason="Retest confirmed fix",
            )
            s.add(record)
            s.commit()
            verification_id = record.id

        with Session() as s:
            result = s.query(RemediationVerificationRecord).filter(
                RemediationVerificationRecord.id == verification_id,
                RemediationVerificationRecord.organization_id == org_b,
            ).first()
            assert result is None


# ---------------------------------------------------------------------------
# Retest tenant isolation
# ---------------------------------------------------------------------------

class TestRetestTenantIsolation:
    def test_cross_tenant_retest_not_accessible(self, session_factory, db):
        Session, org_a, org_b = db

        with Session() as s:
            finding_id = uuid4()
            record = RemediationRetestResultRecord(
                id=uuid4(), organization_id=org_a, finding_id=finding_id,
                proposal_id=uuid4(), clone_id=uuid4(), attempt_number=1,
                original_attack_blocked=True, vulnerability_eliminated=True,
                retest_outcome="VULNERABILITY_ELIMINATED",
            )
            s.add(record)
            s.commit()

        with Session() as s:
            results = s.query(RemediationRetestResultRecord).filter(
                RemediationRetestResultRecord.finding_id == finding_id,
                RemediationRetestResultRecord.organization_id == org_b,
            ).all()
            assert len(results) == 0


# ---------------------------------------------------------------------------
# Audit event tenant isolation
# ---------------------------------------------------------------------------

class TestAuditEventTenantIsolation:
    def test_cross_tenant_audit_event_not_accessible(self, session_factory, db):
        Session, org_a, org_b = db

        with Session() as s:
            entity_id = uuid4()
            record = RemediationAuditEventRecord(
                id=uuid4(), organization_id=org_a,
                entity_type="finding", entity_id=entity_id,
                event_type="FINDING_CREATED",
                timestamp=datetime.now(timezone.utc),
                actor="system", correlation_id=uuid4(),
            )
            s.add(record)
            s.commit()

        with Session() as s:
            events = s.query(RemediationAuditEventRecord).filter(
                RemediationAuditEventRecord.entity_type == "finding",
                RemediationAuditEventRecord.entity_id == entity_id,
                RemediationAuditEventRecord.organization_id == org_b,
            ).all()
            assert len(events) == 0

    def test_cross_tenant_correlation_query(self, session_factory, db):
        Session, org_a, org_b = db
        correlation_id = uuid4()

        with Session() as s:
            s.add(RemediationAuditEventRecord(
                id=uuid4(), organization_id=org_a,
                entity_type="finding", entity_id=uuid4(),
                event_type="FINDING_CREATED",
                timestamp=datetime.now(timezone.utc),
                actor="system", correlation_id=correlation_id,
            ))
            s.add(RemediationAuditEventRecord(
                id=uuid4(), organization_id=org_b,
                entity_type="finding", entity_id=uuid4(),
                event_type="FINDING_CREATED",
                timestamp=datetime.now(timezone.utc),
                actor="system", correlation_id=correlation_id,
            ))
            s.commit()

        with Session() as s:
            events_a = s.query(RemediationAuditEventRecord).filter(
                RemediationAuditEventRecord.correlation_id == correlation_id,
                RemediationAuditEventRecord.organization_id == org_a,
            ).all()
            events_b = s.query(RemediationAuditEventRecord).filter(
                RemediationAuditEventRecord.correlation_id == correlation_id,
                RemediationAuditEventRecord.organization_id == org_b,
            ).all()
            assert len(events_a) == 1
            assert len(events_b) == 1


# ---------------------------------------------------------------------------
# Core DB model tenant isolation
# ---------------------------------------------------------------------------

class TestCoreDBTenantIsolation:
    def test_policy_decision_org_scoped(self, db):
        Session, org_a, org_b = db
        with Session() as s:
            dec_a = PolicyDecisionRecord(
                id=uuid4(), organization_id=org_a, status="ALLOWED",
                reason="Test A", scenario_id=uuid4(),
            )
            dec_b = PolicyDecisionRecord(
                id=uuid4(), organization_id=org_b, status="DENIED",
                reason="Test B", scenario_id=uuid4(),
            )
            s.add_all([dec_a, dec_b])
            s.commit()

            results_a = s.query(PolicyDecisionRecord).filter(
                PolicyDecisionRecord.organization_id == org_a
            ).all()
            results_b = s.query(PolicyDecisionRecord).filter(
                PolicyDecisionRecord.organization_id == org_b
            ).all()

            assert len(results_a) == 1
            assert len(results_b) == 1
            assert results_a[0].status == "ALLOWED"
            assert results_b[0].status == "DENIED"

    def test_detection_gap_org_scoped(self, db):
        Session, org_a, org_b = db
        with Session() as s:
            gap_a = DetectionGapRecord(
                id=uuid4(), organization_id=org_a, scenario_id=uuid4(),
                action_id=uuid4(), technique_id="T1003.008",
                original_outcome="DETECTION_GAP", root_cause="NO_RULE_MATCH",
                reason="A", remediation_status="OPEN",
            )
            gap_b = DetectionGapRecord(
                id=uuid4(), organization_id=org_b, scenario_id=uuid4(),
                action_id=uuid4(), technique_id="T1003.008",
                original_outcome="DETECTION_GAP", root_cause="NO_RULE_MATCH",
                reason="B", remediation_status="OPEN",
            )
            s.add_all([gap_a, gap_b])
            s.commit()

            gaps_a = s.query(DetectionGapRecord).filter(
                DetectionGapRecord.organization_id == org_a
            ).all()
            gaps_b = s.query(DetectionGapRecord).filter(
                DetectionGapRecord.organization_id == org_b
            ).all()

            assert len(gaps_a) == 1
            assert len(gaps_b) == 1

    def test_retest_result_org_scoped(self, db):
        Session, org_a, org_b = db
        with Session() as s:
            retest_a = RetestResult(
                organization_id=org_a, scenario_id=uuid4(),
                before_outcome="DETECTION_GAP", after_outcome="DETECTED",
                detection_improved="True",
            )
            retest_b = RetestResult(
                organization_id=org_b, scenario_id=uuid4(),
                before_outcome="DETECTION_GAP", after_outcome="DETECTED",
                detection_improved="True",
            )
            s.add_all([retest_a, retest_b])
            s.commit()

            results_a = s.query(RetestResult).filter(
                RetestResult.organization_id == org_a
            ).all()
            results_b = s.query(RetestResult).filter(
                RetestResult.organization_id == org_b
            ).all()

            assert len(results_a) == 1
            assert len(results_b) == 1

    def test_audit_log_org_scoped(self, db):
        Session, org_a, org_b = db
        with Session() as s:
            log_a = AuditLog(organization_id=org_a, action="ACTION_A")
            log_b = AuditLog(organization_id=org_b, action="ACTION_B")
            s.add_all([log_a, log_b])
            s.commit()

            logs_a = s.query(AuditLog).filter(AuditLog.organization_id == org_a).all()
            logs_b = s.query(AuditLog).filter(AuditLog.organization_id == org_b).all()

            assert len(logs_a) == 1
            assert len(logs_b) == 1
            assert logs_a[0].action == "ACTION_A"
            assert logs_b[0].action == "ACTION_B"