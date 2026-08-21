"""SentinelForge — Unit Tests for Remediation Proposal Generator."""

import pytest
from uuid import uuid4
from datetime import datetime, timezone, timedelta

from sentinelforge.agents.red.provider import MockProvider
from sentinelforge.remediation.models import (
    ApplicationTarget,
    PatchSpec,
    TargetEnvironment,
    TargetType,
    VulnerabilityCategory,
    VulnerabilityConfidence,
    VulnerabilityFinding,
    VulnerabilitySeverity,
)
from sentinelforge.remediation.proposal_generator import (
    ProposalGenerationError,
    RemediationProposalGenerator,
)


@pytest.fixture
def finding():
    return VulnerabilityFinding(
        finding_id=uuid4(),
        organization_id=uuid4(),
        target_id=uuid4(),
        attack_technique_id="T1190",
        vulnerability_category=VulnerabilityCategory.INJECTION.value,
        affected_component="/login",
        evidence="SQL injection confirmed via f-string",
        severity=VulnerabilitySeverity.HIGH,
        confidence=VulnerabilityConfidence.CONFIRMED,
        reproduction_info="POST /login with malicious payload",
    )


@pytest.fixture
def target():
    return ApplicationTarget(
        target_id=uuid4(),
        organization_id=uuid4(),
        name="Test App",
        target_type=TargetType.DOCKERIZED,
        environment=TargetEnvironment.LAB,
        local_path="/tmp/test",
        authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )


class TestRemediationProposalGenerator:
    def test_generates_proposal_from_json(self, finding, target):
        json_response = '''{
            "root_cause": "SQL injection via f-string",
            "proposed_remediation": "Use parameterized queries",
            "affected_files": ["app.py"],
            "patches": [{"file_path": "app.py", "operation": "modify", "patch_diff": "query = \\"SELECT * FROM users WHERE username=? AND password=?\\""}],
            "expected_security_effect": "Prevents SQL injection",
            "expected_behavior": "Login works normally",
            "test_plan": "Test with injection payloads",
            "rollback_plan": "Revert file",
            "risk_assessment": "Low"
        }'''
        provider = MockProvider(responses=[json_response])
        generator = RemediationProposalGenerator(provider=provider)
        proposal = generator.generate(finding=finding, target=target)
        assert proposal.root_cause == "SQL injection via f-string"
        assert "app.py" in proposal.affected_files

    def test_generates_proposal_with_patches_from_json(self, finding, target):
        json_response = '''{
            "root_cause": "SQL injection via f-string",
            "proposed_remediation": "Use parameterized queries",
            "affected_files": ["app.py"],
            "patches": [{"file_path": "app.py", "operation": "modify", "patch_diff": "query = \\"SELECT * FROM users WHERE username=? AND password=?\\""}],
            "expected_security_effect": "Prevents SQL injection",
            "expected_behavior": "Login works normally",
            "test_plan": "Test with injection payloads",
            "rollback_plan": "Revert file",
            "risk_assessment": "Low"
        }'''
        provider = MockProvider(responses=[json_response])
        generator = RemediationProposalGenerator(provider=provider)
        proposal = generator.generate(finding=finding, target=target)
        assert len(proposal.patches) > 0

    def test_provider_error_raises(self, finding, target):
        provider = MockProvider(fail_after=0)
        generator = RemediationProposalGenerator(provider=provider)
        with pytest.raises(ProposalGenerationError, match="LLM provider error"):
            generator.generate(finding=finding, target=target)
