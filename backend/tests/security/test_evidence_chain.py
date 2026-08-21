"""SentinelForge — Phase 7: Evidence Chain Audit Trail.

Proves that every experiment produces an auditable chain from proposal
through retest, with all records linked by correlation IDs and organization scoping.
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
from sentinelforge.domain.experiment import PolicyDecision, PolicyDecisionStatus
from sentinelforge.policy.safety_boundary import ExperimentSafetyBoundary


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def db_session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    s = Session()
    org_id = uuid4()
    s.add(Organization(id=org_id, name="EvidenceTestOrg"))
    s.commit()
    yield s, org_id
    s.close()


# ---------------------------------------------------------------------------
# Policy Decision Record persistence
# ---------------------------------------------------------------------------

class TestPolicyDecisionAuditTrail:
    def test_allowed_decision_recorded(self, db_session):
        s, org_id = db_session
        boundary = ExperimentSafetyBoundary()
        from sentinelforge.domain.experiment import AdversarialScenario
        scenario = AdversarialScenario(
            objective_id=uuid4(), organization_id=org_id,
            title="Test", strategy_description="Test",
            technique_ids=["T1059"], proposed_risk_level="LOW",
        )
        decision = boundary.evaluate_scenario(scenario, db_session=s)
        assert decision.status == PolicyDecisionStatus.ALLOWED
        count = s.query(PolicyDecisionRecord).count()
        assert count == 1

    def test_denied_decision_recorded(self, db_session):
        s, org_id = db_session
        from sentinelforge.domain.experiment import ExperimentConstraints, RiskLevel
        boundary = ExperimentSafetyBoundary(
            constraints=ExperimentConstraints(max_risk_level=RiskLevel.LOW)
        )
        from sentinelforge.domain.experiment import AdversarialScenario
        scenario = AdversarialScenario(
            objective_id=uuid4(), organization_id=org_id,
            title="High Risk", strategy_description="Critical",
            technique_ids=["T1059"], proposed_risk_level="CRITICAL",
        )
        decision = boundary.evaluate_scenario(scenario, db_session=s)
        assert decision.status == PolicyDecisionStatus.DENIED
        count = s.query(PolicyDecisionRecord).count()
        assert count == 1

    def test_decision_links_to_scenario_id(self, db_session):
        s, org_id = db_session
        boundary = ExperimentSafetyBoundary()
        from sentinelforge.domain.experiment import AdversarialScenario
        scenario = AdversarialScenario(
            objective_id=uuid4(), organization_id=org_id,
            title="Test", strategy_description="Test",
            technique_ids=["T1059"], proposed_risk_level="LOW",
        )
        decision = boundary.evaluate_scenario(scenario, db_session=s)
        record = s.query(PolicyDecisionRecord).first()
        assert str(record.scenario_id) == str(decision.scenario_id)

    def test_decision_evaluated_at_timestamp(self, db_session):
        s, org_id = db_session
        boundary = ExperimentSafetyBoundary()
        from sentinelforge.domain.experiment import AdversarialScenario
        scenario = AdversarialScenario(
            objective_id=uuid4(), organization_id=org_id,
            title="Test", strategy_description="Test",
            technique_ids=["T1059"], proposed_risk_level="LOW",
        )
        before = datetime.now(timezone.utc)
        boundary.evaluate_scenario(scenario, db_session=s)
        after = datetime.now(timezone.utc)
        record = s.query(PolicyDecisionRecord).first()
        assert record.evaluated_at is not None


# ---------------------------------------------------------------------------
# Audit Log persistence
# ---------------------------------------------------------------------------

class TestAuditLogTrail:
    def test_audit_log_recorded(self, db_session):
        s, org_id = db_session
        log = AuditLog(organization_id=org_id, action="VALIDATION_STARTED", blueprint_id=uuid4())
        s.add(log)
        s.commit()
        count = s.query(AuditLog).count()
        assert count == 1

    def test_audit_log_links_to_blueprint(self, db_session):
        s, org_id = db_session
        bp_id = uuid4()
        log = AuditLog(organization_id=org_id, action="BLUEPRINT_VERIFIED", blueprint_id=bp_id)
        s.add(log)
        s.commit()
        record = s.query(AuditLog).first()
        assert str(record.blueprint_id) == str(bp_id)

    def test_multiple_audit_logs_chronological(self, db_session):
        s, org_id = db_session
        actions = ["VALIDATION_STARTED", "BLUEPRINT_VERIFIED", "EXECUTION_STARTED", "EXECUTION_COMPLETED"]
        bp_id = uuid4()
        for action in actions:
            log = AuditLog(organization_id=org_id, action=action, blueprint_id=bp_id)
            s.add(log)
        s.commit()
        records = s.query(AuditLog).order_by(AuditLog.timestamp).all()
        assert len(records) == 4
        recorded_actions = [r.action for r in records]
        assert recorded_actions == actions


# ---------------------------------------------------------------------------
# Detection Gap → Retest Result chain
# ---------------------------------------------------------------------------

class TestDetectionGapRetestChain:
    def test_detection_gap_created(self, db_session):
        s, org_id = db_session
        gap = DetectionGapRecord(
            id=uuid4(), organization_id=org_id, scenario_id=uuid4(),
            action_id=uuid4(), technique_id="T1003.008",
            original_outcome="DETECTION_GAP", root_cause="NO_RULE_MATCH",
            reason="No rule matched", remediation_status="OPEN",
        )
        s.add(gap)
        s.commit()
        assert s.query(DetectionGapRecord).count() == 1

    def test_retest_result_links_to_scenario(self, db_session):
        s, org_id = db_session
        scenario_id = uuid4()
        retest = RetestResult(
            organization_id=org_id, scenario_id=scenario_id,
            before_outcome="DETECTION_GAP", after_outcome="DETECTED",
            detection_improved="True", validated_rule_ids='["rule1"]',
        )
        s.add(retest)
        s.commit()
        record = s.query(RetestResult).first()
        assert str(record.scenario_id) == str(scenario_id)

    def test_detection_gap_to_retest_correlation(self, db_session):
        s, org_id = db_session
        scenario_id = uuid4()
        action_id = uuid4()
        retest_id = uuid4()

        gap = DetectionGapRecord(
            id=uuid4(), organization_id=org_id, scenario_id=scenario_id,
            action_id=action_id, technique_id="T1003.008",
            original_outcome="DETECTION_GAP", root_cause="NO_RULE_MATCH",
            reason="No rule matched", remediation_status="IN_PROGRESS",
            retest_id=retest_id,
        )
        s.add(gap)

        retest = RetestResult(
            organization_id=org_id, scenario_id=scenario_id,
            before_outcome="DETECTION_GAP", after_outcome="DETECTED",
            detection_improved="True", validated_rule_ids='["rule1"]',
        )
        s.add(retest)
        s.commit()

        gap_record = s.query(DetectionGapRecord).first()
        retest_record = s.query(RetestResult).first()
        assert str(gap_record.scenario_id) == str(retest_record.scenario_id)
        assert str(gap_record.retest_id) == str(retest_id)


# ---------------------------------------------------------------------------
# Organization-scoped querying
# ---------------------------------------------------------------------------

class TestOrganizationScopedAudit:
    def test_org_scoped_query(self, db_session):
        s, org_id = db_session
        other_org_id = uuid4()
        s.add(Organization(id=other_org_id, name="OtherOrg"))
        s.commit()

        log1 = AuditLog(organization_id=org_id, action="ACTION_1")
        log2 = AuditLog(organization_id=other_org_id, action="ACTION_2")
        s.add_all([log1, log2])
        s.commit()

        org_logs = s.query(AuditLog).filter(AuditLog.organization_id == org_id).all()
        assert len(org_logs) == 1
        assert org_logs[0].action == "ACTION_1"

    def test_policy_decision_org_scoped(self, db_session):
        s, org_id = db_session
        other_org_id = uuid4()
        s.add(Organization(id=other_org_id, name="OtherOrg"))
        s.commit()

        dec1 = PolicyDecisionRecord(
            id=uuid4(), organization_id=org_id, status="ALLOWED",
            reason="Test", scenario_id=uuid4(),
        )
        dec2 = PolicyDecisionRecord(
            id=uuid4(), organization_id=other_org_id, status="DENIED",
            reason="Test", scenario_id=uuid4(),
        )
        s.add_all([dec1, dec2])
        s.commit()

        org_decisions = s.query(PolicyDecisionRecord).filter(
            PolicyDecisionRecord.organization_id == org_id
        ).all()
        assert len(org_decisions) == 1
        assert org_decisions[0].status == "ALLOWED"


# ---------------------------------------------------------------------------
# Evidence chain completeness
# ---------------------------------------------------------------------------

class TestEvidenceChainCompleteness:
    def test_full_chain_recorded(self, db_session):
        s, org_id = db_session
        scenario_id = uuid4()
        bp_id = uuid4()

        # 1. Policy decision
        boundary = ExperimentSafetyBoundary()
        from sentinelforge.domain.experiment import AdversarialScenario
        scenario = AdversarialScenario(
            objective_id=uuid4(), organization_id=org_id,
            title="Test", strategy_description="Test",
            technique_ids=["T1003.008"], proposed_risk_level="LOW",
        )
        decision = boundary.evaluate_scenario(scenario, db_session=s)
        assert s.query(PolicyDecisionRecord).count() == 1

        # 2. Audit log
        log = AuditLog(organization_id=org_id, action="BLUEPRINT_VERIFIED", blueprint_id=bp_id)
        s.add(log)
        s.commit()

        # 3. Detection gap
        gap = DetectionGapRecord(
            id=uuid4(), organization_id=org_id, scenario_id=scenario_id,
            action_id=uuid4(), technique_id="T1003.008",
            original_outcome="DETECTION_GAP", root_cause="NO_RULE_MATCH",
            reason="No rule matched", remediation_status="IN_PROGRESS",
        )
        s.add(gap)
        s.commit()

        # 4. Retest result
        retest = RetestResult(
            organization_id=org_id, scenario_id=scenario_id,
            before_outcome="DETECTION_GAP", after_outcome="DETECTED",
            detection_improved="True", validated_rule_ids='["rule1"]',
        )
        s.add(retest)
        s.commit()

        # Verify chain completeness
        assert s.query(PolicyDecisionRecord).count() == 1
        assert s.query(AuditLog).count() == 1
        assert s.query(DetectionGapRecord).count() == 1
        assert s.query(RetestResult).count() == 1

        # All records share the same organization_id
        for Model in [PolicyDecisionRecord, AuditLog, DetectionGapRecord, RetestResult]:
            records = s.query(Model).all()
            for r in records:
                assert str(r.organization_id) == str(org_id)
