"""SentinelForge — Comprehensive Persistence Tests.

Covers: unit tests for all persistence classes, tenant isolation,
state transitions, idempotency, failure recovery, and E2E audit trail.
"""

import json
import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from sentinelforge.remediation.persistence import (
    AuditEventPersistence,
    AuditEventType,
    AttemptPersistence,
    FindingPersistence,
    ProposalPersistence,
    RetestPersistence,
    VerificationPersistence,
    _sanitize_metadata,
    _validate_transition,
)
from sentinelforge.remediation.models import (
    ApplicationTarget,
    PatchSpec,
    RemediationBudget,
    RemediationProposal,
    RemediationOutcome,
    TargetEnvironment,
    TargetType,
    VulnerabilityCategory,
    VulnerabilityConfidence,
    VulnerabilityFinding,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from sentinelforge.remediation.clone_manager import CloneManager
from sentinelforge.remediation.executor import CloneRemediationExecutor
from sentinelforge.remediation.orchestrator import RemediationOrchestrator
from sentinelforge.remediation.retest import VulnerabilityRetestOrchestrator


# ---------------------------------------------------------------------------
# UNIT: State transitions
# ---------------------------------------------------------------------------

class TestStateTransitions:
    def test_valid_proposed_to_validated(self):
        assert _validate_transition("PROPOSED", "VALIDATED")

    def test_valid_proposed_to_rejected(self):
        assert _validate_transition("PROPOSED", "REJECTED")

    def test_valid_validated_to_applied(self):
        assert _validate_transition("VALIDATED", "APPLIED")

    def test_valid_applied_to_testing(self):
        assert _validate_transition("APPLIED", "TESTING")

    def test_valid_testing_to_retesting(self):
        assert _validate_transition("TESTING", "RETESTING")

    def test_valid_retesting_to_verified(self):
        assert _validate_transition("RETESTING", "VERIFIED")

    def test_valid_retesting_to_failed(self):
        assert _validate_transition("RETESTING", "FAILED")

    def test_invalid_proposed_to_verified(self):
        assert not _validate_transition("PROPOSED", "VERIFIED")

    def test_invalid_verified_to_anything(self):
        assert not _validate_transition("VERIFIED", "FAILED")
        assert not _validate_transition("VERIFIED", "PROPOSED")

    def test_invalid_failed_to_anything(self):
        assert not _validate_transition("FAILED", "VERIFIED")
        assert not _validate_transition("FAILED", "APPLIED")

    def test_rollback_to_proposed(self):
        assert _validate_transition("ROLLED_BACK", "PROPOSED")


# ---------------------------------------------------------------------------
# UNIT: Metadata sanitization
# ---------------------------------------------------------------------------

class TestMetadataSanitization:
    def test_api_key_redacted(self):
        result = _sanitize_metadata({"api_key": "sk-12345", "user_id": "abc"})
        assert result["api_key"] == "[REDACTED]"
        assert result["user_id"] == "abc"

    def test_password_redacted(self):
        result = _sanitize_metadata({"password": "secret123"})
        assert result["password"] == "[REDACTED]"

    def test_token_redacted(self):
        result = _sanitize_metadata({"auth_token": "tok_abc"})
        assert result["auth_token"] == "[REDACTED]"

    def test_empty_metadata(self):
        assert _sanitize_metadata(None) == {}
        assert _sanitize_metadata({}) == {}


# ---------------------------------------------------------------------------
# UNIT: Finding persistence
# ---------------------------------------------------------------------------

class TestFindingPersistence:
    def test_create_and_get(self, test_session_factory):
        store = FindingPersistence(test_session_factory)
        org = uuid4()
        target = uuid4()
        record = store.create(org, target, "T1190", "A03_INJECTION", "/login", "evidence")
        assert record.id is not None
        assert record.organization_id == org
        retrieved = store.get(record.id, org)
        assert retrieved is not None
        assert retrieved.evidence == "evidence"

    def test_get_wrong_org_returns_none(self, test_session_factory):
        store = FindingPersistence(test_session_factory)
        org_a, org_b = uuid4(), uuid4()
        record = store.create(org_a, uuid4(), "T1190", "A03_INJECTION", "/login", "ev")
        assert store.get(record.id, org_b) is None

    def test_update_status(self, test_session_factory):
        store = FindingPersistence(test_session_factory)
        record = store.create(uuid4(), uuid4(), "T1190", "A03_INJECTION", "/login", "ev")
        updated = store.update_status(record.id, record.organization_id, "REMEDIATING")
        assert updated.status == "REMEDIATING"

    def test_list_by_organization(self, test_session_factory):
        store = FindingPersistence(test_session_factory)
        org = uuid4()
        store.create(org, uuid4(), "T1190", "A03_INJECTION", "/a", "ev1")
        store.create(org, uuid4(), "T1190", "A03_INJECTION", "/b", "ev2")
        store.create(uuid4(), uuid4(), "T1190", "A03_INJECTION", "/c", "ev3")
        results = store.get_by_organization(org)
        assert len(results) == 2


# ---------------------------------------------------------------------------
# UNIT: Proposal persistence
# ---------------------------------------------------------------------------

class TestProposalPersistence:
    def test_create_and_get(self, test_session_factory):
        store = ProposalPersistence(test_session_factory)
        org = uuid4()
        record = store.create(org, uuid4(), uuid4(), "rc", "pr", ["f.py"], "[]", "se", "eb", "tp", "rp", "ra")
        assert record.id is not None
        assert record.status == "CREATED"

    def test_update_status(self, test_session_factory):
        store = ProposalPersistence(test_session_factory)
        record = store.create(uuid4(), uuid4(), uuid4(), "rc", "pr", ["f.py"], "[]", "se", "eb", "tp", "rp", "ra")
        updated = store.update_status(record.id, record.organization_id, "VALIDATED")
        assert updated.status == "VALIDATED"


# ---------------------------------------------------------------------------
# UNIT: Attempt persistence + state transitions
# ---------------------------------------------------------------------------

class TestAttemptPersistence:
    def test_create_and_get(self, test_session_factory):
        store = AttemptPersistence(test_session_factory)
        record = store.create(uuid4(), uuid4(), uuid4(), uuid4(), 1)
        assert record.status == "PROPOSED"
        assert record.attempt_number == 1

    def test_valid_state_transition(self, test_session_factory):
        store = AttemptPersistence(test_session_factory)
        record = store.create(uuid4(), uuid4(), uuid4(), uuid4(), 1)
        updated = store.update_status(record.id, record.organization_id, "VALIDATED")
        assert updated.status == "VALIDATED"

    def test_invalid_state_transition_raises(self, test_session_factory):
        store = AttemptPersistence(test_session_factory)
        record = store.create(uuid4(), uuid4(), uuid4(), uuid4(), 1)
        with pytest.raises(ValueError, match="Invalid transition"):
            store.update_status(record.id, record.organization_id, "VERIFIED")

    def test_terminal_states_cannot_transition(self, test_session_factory):
        store = AttemptPersistence(test_session_factory)
        record = store.create(uuid4(), uuid4(), uuid4(), uuid4(), 1)
        store.update_status(record.id, record.organization_id, "VALIDATED")
        store.update_status(record.id, record.organization_id, "APPLIED")
        store.update_status(record.id, record.organization_id, "TESTING")
        store.update_status(record.id, record.organization_id, "RETESTING")
        store.update_status(record.id, record.organization_id, "VERIFIED")
        with pytest.raises(ValueError, match="Invalid transition"):
            store.update_status(record.id, record.organization_id, "FAILED")

    def test_end_time_set_on_terminal_state(self, test_session_factory):
        store = AttemptPersistence(test_session_factory)
        record = store.create(uuid4(), uuid4(), uuid4(), uuid4(), 1)
        store.update_status(record.id, record.organization_id, "VALIDATED")
        store.update_status(record.id, record.organization_id, "APPLIED")
        store.update_status(record.id, record.organization_id, "TESTING")
        store.update_status(record.id, record.organization_id, "RETESTING")
        final = store.update_status(record.id, record.organization_id, "VERIFIED")
        assert final.end_time is not None


# ---------------------------------------------------------------------------
# UNIT: Verification persistence
# ---------------------------------------------------------------------------

class TestVerificationPersistence:
    def test_create_and_get(self, test_session_factory):
        store = VerificationPersistence(test_session_factory)
        record = store.create(
            organization_id=uuid4(), finding_id=uuid4(),
            remediation_attempt_id=uuid4(), original_attack_blocked=True,
            retest_outcome="VERIFIED", verification_decision="VERIFIED",
            verification_reason="All tests passed",
        )
        assert record.verification_decision == "VERIFIED"

    def test_get_by_finding(self, test_session_factory):
        store = VerificationPersistence(test_session_factory)
        org, finding = uuid4(), uuid4()
        store.create(org, finding, uuid4(), True, "VERIFIED", "VERIFIED", "r1")
        store.create(org, uuid4(), uuid4(), False, "FAILED", "FAILED", "r2")
        results = store.get_by_finding(finding, org)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# UNIT: Audit event persistence
# ---------------------------------------------------------------------------

class TestAuditEventPersistence:
    def test_record_event(self, test_session_factory):
        store = AuditEventPersistence(test_session_factory)
        event = store.record(uuid4(), "Finding", uuid4(), AuditEventType.FINDING_CREATED, uuid4())
        assert event.event_type == AuditEventType.FINDING_CREATED

    def test_get_by_entity(self, test_session_factory):
        store = AuditEventPersistence(test_session_factory)
        org, entity, corr = uuid4(), uuid4(), uuid4()
        store.record(org, "Finding", entity, AuditEventType.FINDING_CREATED, corr)
        store.record(org, "Finding", entity, AuditEventType.REMEDIATION_PROPOSED, corr)
        store.record(org, "Finding", uuid4(), AuditEventType.FINDING_CREATED, corr)
        events = store.get_by_entity("Finding", entity, org)
        assert len(events) == 2

    def test_get_by_correlation(self, test_session_factory):
        store = AuditEventPersistence(test_session_factory)
        org, corr = uuid4(), uuid4()
        store.record(org, "A", uuid4(), AuditEventType.CLONE_CREATED, corr)
        store.record(org, "B", uuid4(), AuditEventType.PATCH_APPLIED, corr)
        store.record(org, "C", uuid4(), AuditEventType.BUILD_PASSED, uuid4())
        events = store.get_by_correlation(corr, org)
        assert len(events) == 2

    def test_secrets_redacted_in_metadata(self, test_session_factory):
        store = AuditEventPersistence(test_session_factory)
        event = store.record(
            uuid4(), "Test", uuid4(), "TEST_EVENT", uuid4(),
            metadata={"api_key": "sk-secret", "safe_data": "ok"},
        )
        meta = json.loads(event.metadata_json)
        assert meta["api_key"] == "[REDACTED]"
        assert meta["safe_data"] == "ok"


# ---------------------------------------------------------------------------
# UNIT: Idempotency
# ---------------------------------------------------------------------------

class TestIdempotency:
    def test_duplicate_finding_creation(self, test_session_factory):
        store = FindingPersistence(test_session_factory)
        org, target = uuid4(), uuid4()
        r1 = store.create(org, target, "T1190", "A03_INJECTION", "/login", "ev1")
        r2 = store.create(org, target, "T1190", "A03_INJECTION", "/login", "ev1")
        assert r1.id != r2.id
        assert store.get(r1.id, org) is not None
        assert store.get(r2.id, org) is not None

    def test_duplicate_proposal_creation(self, test_session_factory):
        store = ProposalPersistence(test_session_factory)
        org, finding = uuid4(), uuid4()
        r1 = store.create(org, finding, uuid4(), "rc", "pr", ["f.py"], "[]", "se", "eb", "tp", "rp", "ra")
        r2 = store.create(org, finding, uuid4(), "rc", "pr", ["f.py"], "[]", "se", "eb", "tp", "rp", "ra")
        assert r1.id != r2.id

    def test_same_correlation_id_audit_events(self, test_session_factory):
        store = AuditEventPersistence(test_session_factory)
        org, corr = uuid4(), uuid4()
        store.record(org, "A", uuid4(), AuditEventType.CLONE_CREATED, corr)
        store.record(org, "A", uuid4(), AuditEventType.CLONE_CREATED, corr)
        events = store.get_by_correlation(corr, org)
        assert len(events) == 2


# ---------------------------------------------------------------------------
# INTEGRATION: Full orchestrator persistence
# ---------------------------------------------------------------------------

class TestOrchestratorPersistence:
    def _make_target(self, tmp_path):
        app_dir = tmp_path / "app"
        app_dir.mkdir(exist_ok=True)
        (app_dir / "app.py").write_text('''from flask import Flask, request
app = Flask(__name__)
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        return f"SELECT * FROM users WHERE username='"'"'{username}'"'"'"
    return "Login page"
@app.route("/index")
def index(): return "Index"
@app.route("/health")
def health(): return "ok"
''')
        return ApplicationTarget(
            target_id=uuid4(), organization_id=uuid4(),
            name="Test", target_type=TargetType.DOCKERIZED,
            environment=TargetEnvironment.LAB,
            local_path=str(app_dir),
            authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )

    def _make_proposal(self, target):
        remediated = '''from flask import Flask, request
app = Flask(__name__)
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        return "SELECT * FROM users WHERE username=? AND password=?"
    return "Login page"
@app.route("/index")
def index(): return "Index"
@app.route("/health")
def health(): return "ok"
'''
        return RemediationProposal(
            proposal_id=uuid4(), finding_id=uuid4(),
            organization_id=target.organization_id,
            root_cause="SQL injection via f-string",
            proposed_remediation="Use parameterized queries",
            affected_files=["app.py"],
            patches=[PatchSpec(file_path="app.py", operation="modify", patch_diff=remediated)],
            expected_security_effect="Prevents SQLi",
            expected_behavior="Login works",
            test_plan="Test with payloads",
            rollback_plan="Revert file",
            risk_assessment="Low",
        )

    def test_orchestrator_persists_audit_trail(self, test_session_factory, tmp_path):
        target = self._make_target(tmp_path)
        proposal = self._make_proposal(target)
        finding = VulnerabilityFinding(
            finding_id=proposal.finding_id, organization_id=target.organization_id,
            target_id=target.target_id, attack_technique_id="T1190",
            vulnerability_category="A03_INJECTION", affected_component="/login",
            evidence="SQL injection confirmed", reproduction_info="POST /login with payload",
        )
        orchestrator = RemediationOrchestrator(
            persistence_factory=test_session_factory,
            budget=RemediationBudget(max_iterations=1, max_variants_per_retest=1),
        )
        orchestrator.remediate_vulnerability(finding, target, proposal)

        audit = AuditEventPersistence(test_session_factory)
        events = audit.get_by_organization(target.organization_id)
        event_types = [e.event_type for e in events]
        assert AuditEventType.FINDING_CREATED in event_types
        assert AuditEventType.CLONE_CREATED in event_types
        assert AuditEventType.REMEDIATION_VALIDATED in event_types
        assert AuditEventType.CLONE_DESTROYED in event_types

    def test_orchestrator_persists_attempt(self, test_session_factory, tmp_path):
        target = self._make_target(tmp_path)
        proposal = self._make_proposal(target)
        finding = VulnerabilityFinding(
            finding_id=proposal.finding_id, organization_id=target.organization_id,
            target_id=target.target_id, attack_technique_id="T1190",
            vulnerability_category="A03_INJECTION", affected_component="/login",
            evidence="SQL injection confirmed", reproduction_info="POST /login with payload",
        )
        orchestrator = RemediationOrchestrator(
            persistence_factory=test_session_factory,
            budget=RemediationBudget(max_iterations=1, max_variants_per_retest=1),
        )
        orchestrator.remediate_vulnerability(finding, target, proposal)

        attempts = AttemptPersistence(test_session_factory).get_by_organization(target.organization_id)
        assert len(attempts) >= 1

    def test_orchestrator_persists_retest(self, test_session_factory, tmp_path):
        target = self._make_target(tmp_path)
        proposal = self._make_proposal(target)
        finding = VulnerabilityFinding(
            finding_id=proposal.finding_id, organization_id=target.organization_id,
            target_id=target.target_id, attack_technique_id="T1190",
            vulnerability_category="A03_INJECTION", affected_component="/login",
            evidence="SQL injection confirmed", reproduction_info="POST /login with payload",
        )
        orchestrator = RemediationOrchestrator(
            persistence_factory=test_session_factory,
            budget=RemediationBudget(max_iterations=1, max_variants_per_retest=1),
        )
        orchestrator.remediate_vulnerability(finding, target, proposal)

        retests = RetestPersistence(test_session_factory).get_by_finding(finding.finding_id, target.organization_id)
        assert len(retests) >= 1


# ---------------------------------------------------------------------------
# FAILURE: Database does not produce false VERIFIED
# ---------------------------------------------------------------------------

class TestFailureRecovery:
    def test_policy_violation_not_verified(self, test_session_factory, tmp_path):
        org = uuid4()
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "app.py").write_text("x = 1")

        target = ApplicationTarget(
            target_id=uuid4(), organization_id=org,
            name="Test", target_type=TargetType.DOCKERIZED,
            environment=TargetEnvironment.LAB,
            local_path=str(app_dir),
            authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        proposal = RemediationProposal(
            proposal_id=uuid4(), finding_id=uuid4(), organization_id=org,
            root_cause="test", proposed_remediation="test",
            affected_files=["../../etc/passwd"],
            patches=[PatchSpec(file_path="../../etc/passwd", operation="modify", patch_diff="x")],
            expected_security_effect="test", expected_behavior="test",
            test_plan="test", rollback_plan="test", risk_assessment="Low",
        )
        finding = VulnerabilityFinding(
            finding_id=proposal.finding_id, organization_id=org,
            target_id=target.target_id, attack_technique_id="T1190",
            vulnerability_category="A03_INJECTION", affected_component="/test",
            evidence="test", reproduction_info="test",
        )
        orchestrator = RemediationOrchestrator(
            persistence_factory=test_session_factory,
            budget=RemediationBudget(max_iterations=1),
        )
        outcome = orchestrator.remediate_vulnerability(finding, target, proposal)
        assert outcome == RemediationOutcome.REMEDIATION_FAILED

        verifications = VerificationPersistence(test_session_factory).get_by_finding(finding.finding_id, org)
        assert len(verifications) == 0

    def test_build_failure_not_verified(self, test_session_factory, tmp_path):
        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "app.py").write_text("x = 1")

        target = ApplicationTarget(
            target_id=uuid4(), organization_id=uuid4(),
            name="Test", target_type=TargetType.DOCKERIZED,
            environment=TargetEnvironment.LAB,
            local_path=str(app_dir),
            authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        proposal = RemediationProposal(
            proposal_id=uuid4(), finding_id=uuid4(), organization_id=target.organization_id,
            root_cause="test", proposed_remediation="test",
            affected_files=["app.py"],
            patches=[PatchSpec(file_path="app.py", operation="modify", patch_diff="def broken(")],
            expected_security_effect="test", expected_behavior="test",
            test_plan="test", rollback_plan="test", risk_assessment="Low",
        )
        finding = VulnerabilityFinding(
            finding_id=proposal.finding_id, organization_id=target.organization_id,
            target_id=target.target_id, attack_technique_id="T1190",
            vulnerability_category="A03_INJECTION", affected_component="/test",
            evidence="test", reproduction_info="test",
        )
        orchestrator = RemediationOrchestrator(
            persistence_factory=test_session_factory,
            budget=RemediationBudget(max_iterations=1),
        )
        outcome = orchestrator.remediate_vulnerability(finding, target, proposal)
        assert outcome != RemediationOutcome.VERIFIED

        attempts = AttemptPersistence(test_session_factory).get_by_finding(finding.finding_id, target.organization_id)
        for attempt in attempts:
            assert attempt.status != "VERIFIED"


# ---------------------------------------------------------------------------
# E2E: Complete audit trail reconstruction
# ---------------------------------------------------------------------------

class TestE2EAuditTrail:
    def test_full_audit_trail_reconstruction(self, test_session_factory, tmp_path):
        org = uuid4()
        target_id = uuid4()

        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "app.py").write_text('''from flask import Flask, request
app = Flask(__name__)
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        return "SELECT * FROM users WHERE username='"'"'{request.form.get("username", "")}'"'"'"
    return "Login page"
@app.route("/index")
def index(): return "Index"
@app.route("/health")
def health(): return "ok"
''')

        finding_store = FindingPersistence(test_session_factory)
        finding_record = finding_store.create(
            organization_id=org, target_id=target_id,
            attack_technique_id="T1190", vulnerability_category="A03_INJECTION",
            affected_component="/login", evidence="SQL injection confirmed via POST /login",
            severity="HIGH", confidence="CONFIRMED",
            reproduction_info="POST /login username=admin' OR '1'='1",
        )

        proposal_store = ProposalPersistence(test_session_factory)
        proposal_record = proposal_store.create(
            organization_id=org, finding_id=finding_record.id, target_id=target_id,
            root_cause="SQL injection via f-string interpolation",
            proposed_remediation="Use parameterized queries with ? placeholders",
            affected_files=["app.py"], patches_json="[]",
            expected_security_effect="Prevents SQL injection",
            expected_behavior="Login still works",
            test_plan="Test with SQL payloads",
            rollback_plan="Revert to original file", risk_assessment="Low",
        )

        audit_store = AuditEventPersistence(test_session_factory)
        correlation_id = uuid4()
        audit_store.record(org, "Finding", finding_record.id, AuditEventType.FINDING_CREATED, correlation_id)
        audit_store.record(org, "Proposal", proposal_record.id, AuditEventType.REMEDIATION_PROPOSED, correlation_id)
        audit_store.record(org, "Proposal", proposal_record.id, AuditEventType.REMEDIATION_VALIDATED, correlation_id)
        audit_store.record(org, "Finding", finding_record.id, AuditEventType.REMEDIATION_PROPOSED, correlation_id)

        attempt_store = AttemptPersistence(test_session_factory)
        attempt = attempt_store.create(org, finding_record.id, proposal_record.id, uuid4(), 1)
        attempt_store.update_status(attempt.id, org, "VALIDATED")
        attempt_store.update_status(attempt.id, org, "APPLIED",
                                    changes_applied=True, build_passed=True, tests_passed=True)
        attempt_store.update_status(attempt.id, org, "TESTING")

        retest_store = RetestPersistence(test_session_factory)
        retest_store.create(
            organization_id=org, finding_id=finding_record.id,
            proposal_id=proposal_record.id, clone_id=uuid4(),
            attempt_number=1, original_attack_blocked=True,
            vulnerability_eliminated=True, retest_outcome="VERIFIED",
        )

        attempt_store.update_status(attempt.id, org, "RETESTING")
        attempt_store.update_status(attempt.id, org, "VERIFIED")

        verification_store = VerificationPersistence(test_session_factory)
        verification_store.create(
            organization_id=org, finding_id=finding_record.id,
            remediation_attempt_id=attempt.id,
            original_attack_blocked=True, retest_outcome="VERIFIED",
            verification_decision="VERIFIED",
            verification_reason="Parameterized queries prevent SQL injection",
            regression_tests_passed=True, application_functional=True,
        )

        audit_store.record(org, "Attempt", attempt.id, AuditEventType.VERIFICATION_PASSED, correlation_id)

        # RECONSTRUCT
        finding = finding_store.get(finding_record.id, org)
        assert finding.vulnerability_category == "A03_INJECTION"
        assert finding.severity == "HIGH"
        assert "SQL injection confirmed" in finding.evidence

        proposal = proposal_store.get(proposal_record.id, org)
        assert "parameterized queries" in proposal.proposed_remediation

        attempts = attempt_store.get_by_finding(finding_record.id, org)
        assert len(attempts) == 1
        assert attempts[0].changes_applied is True

        retests = retest_store.get_by_finding(finding_record.id, org)
        assert len(retests) == 1
        assert retests[0].vulnerability_eliminated is True

        verifications = verification_store.get_by_finding(finding_record.id, org)
        assert len(verifications) == 1
        assert verifications[0].verification_decision == "VERIFIED"

        events = audit_store.get_by_correlation(correlation_id, org)
        event_types = [e.event_type for e in events]
        assert AuditEventType.FINDING_CREATED in event_types
        assert AuditEventType.REMEDIATION_PROPOSED in event_types
        assert AuditEventType.VERIFICATION_PASSED in event_types

        all_events = audit_store.get_by_organization(org)
        assert len(all_events) >= 5
