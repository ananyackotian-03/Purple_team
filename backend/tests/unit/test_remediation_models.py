"""SentinelForge Branch 2 — Unit Tests for Domain Models."""

import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from sentinelforge.remediation.models import (
    ApplicationTarget,
    CloneSnapshot,
    CloneStatus,
    PatchSpec,
    RemediationBudget,
    RemediationExecutionResult,
    RemediationOutcome,
    RemediationProposal,
    TargetClone,
    TargetEnvironment,
    TargetType,
    VulnerabilityCategory,
    VulnerabilityConfidence,
    VulnerabilityFinding,
    VulnerabilityRetestResult,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)


class TestVulnerabilityFinding:
    def test_create_finding(self):
        finding = VulnerabilityFinding(
            finding_id=uuid4(),
            organization_id=uuid4(),
            target_id=uuid4(),
            attack_technique_id="T1190",
            vulnerability_category=VulnerabilityCategory.INJECTION.value,
            affected_component="/login",
            evidence="SQL injection successful with payload ' OR '1'='1",
            severity=VulnerabilitySeverity.HIGH,
            confidence=VulnerabilityConfidence.CONFIRMED,
            reproduction_info="POST /login with malicious payload",
            status=VulnerabilityStatus.OPEN,
        )
        assert finding.vulnerability_category == VulnerabilityCategory.INJECTION.value
        assert finding.severity == VulnerabilitySeverity.HIGH
        assert finding.status == VulnerabilityStatus.OPEN
        assert finding.iteration_count == 0
        assert finding.max_iterations == 3

    def test_finding_defaults(self):
        finding = VulnerabilityFinding(
            finding_id=uuid4(),
            organization_id=uuid4(),
            target_id=uuid4(),
            attack_technique_id="T1190",
            vulnerability_category=VulnerabilityCategory.INJECTION.value,
            affected_component="/login",
            evidence="test",
            reproduction_info="test",
        )
        assert finding.severity == VulnerabilitySeverity.MEDIUM
        assert finding.confidence == VulnerabilityConfidence.SUSPECTED
        assert finding.status == VulnerabilityStatus.OPEN


class TestApplicationTarget:
    def test_lab_target(self):
        target = ApplicationTarget(
            target_id=uuid4(),
            organization_id=uuid4(),
            name="Test App",
            target_type=TargetType.DOCKERIZED,
            environment=TargetEnvironment.LAB,
            local_path="/tmp/test_app",
            authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert target.environment == TargetEnvironment.LAB
        assert target.is_active is True

    def test_production_target_readonly(self):
        target = ApplicationTarget(
            target_id=uuid4(),
            organization_id=uuid4(),
            name="Prod App",
            target_type=TargetType.DOCKERIZED,
            environment=TargetEnvironment.PRODUCTION,
            local_path="/opt/prod_app",
            authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        assert target.environment == TargetEnvironment.PRODUCTION


class TestTargetClone:
    def test_clone_status(self):
        clone = TargetClone(
            clone_id=uuid4(),
            organization_id=uuid4(),
            source_target_id=uuid4(),
            source_revision="abc123",
            status=CloneStatus.CREATING,
        )
        assert clone.status == CloneStatus.CREATING
        assert clone.current_version == 1

    def test_clone_ready(self):
        clone = TargetClone(
            clone_id=uuid4(),
            organization_id=uuid4(),
            source_target_id=uuid4(),
            source_revision="abc123",
            status=CloneStatus.READY,
        )
        assert clone.status == CloneStatus.READY


class TestRemediationProposal:
    def test_valid_proposal(self):
        proposal = RemediationProposal(
            proposal_id=uuid4(),
            finding_id=uuid4(),
            organization_id=uuid4(),
            root_cause="SQL injection via string formatting",
            proposed_remediation="Use parameterized queries",
            affected_files=["app.py"],
            patches=[
                PatchSpec(
                    file_path="app.py",
                    operation="modify",
                    patch_diff="query = 'SELECT * FROM users WHERE username=? AND password=?'",
                )
            ],
            expected_security_effect="Prevents SQL injection",
            expected_behavior="Login still works",
            test_plan="Test with malicious payloads",
            rollback_plan="Revert file changes",
            risk_assessment="Low risk",
        )
        assert proposal.schema_validated is False
        assert proposal.policy_validated is False
        assert proposal.clone_validated is False


class TestRemediationBudget:
    def test_budget_defaults(self):
        budget = RemediationBudget()
        assert budget.max_iterations == 3
        assert budget.max_llm_calls == 10
        assert budget.max_wall_time_seconds == 600
        assert budget.max_variants_per_retest == 3

    def test_budget_has_remaining(self):
        budget = RemediationBudget(max_iterations=5, max_llm_calls=10)
        started_at = datetime.now(timezone.utc)
        assert budget.has_remaining(iteration=1, llm_calls=1, started_at=started_at) is True
        assert budget.has_remaining(iteration=4, llm_calls=8, started_at=started_at) is True
        assert budget.has_remaining(iteration=5, llm_calls=1, started_at=started_at) is False
        assert budget.has_remaining(iteration=1, llm_calls=10, started_at=started_at) is False

    def test_budget_time_limit(self):
        budget = RemediationBudget(max_wall_time_seconds=60)
        started_at = datetime.now(timezone.utc) - timedelta(seconds=120)
        assert budget.has_remaining(iteration=1, llm_calls=1, started_at=started_at) is False


class TestRemediationOutcome:
    def test_outcomes(self):
        assert RemediationOutcome.VERIFIED.value == "VERIFIED"
        assert RemediationOutcome.FAILED.value == "FAILED"
        assert RemediationOutcome.REMEDIATION_FAILED.value == "REMEDIATION_FAILED"
        assert RemediationOutcome.REQUIRES_HUMAN_REVIEW.value == "REQUIRES_HUMAN_REVIEW"
        assert RemediationOutcome.BUDGET_EXHAUSTED.value == "BUDGET_EXHAUSTED"
