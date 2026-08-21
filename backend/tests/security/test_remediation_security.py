"""SentinelForge Branch 2 — Security Tests for Remediation Policy."""

import pytest
from uuid import uuid4

from sentinelforge.remediation.models import PatchSpec, RemediationProposal
from sentinelforge.remediation.policy import RemediationPolicy, RemediationPolicyValidator


def _make_proposal(files=None, patches=None, remediation_text="test", patch_diff="x = 1"):
    if files is None:
        files = ["app.py"]
    if patches is None:
        patches = [PatchSpec(file_path="app.py", operation="modify", patch_diff=patch_diff)]
    return RemediationProposal(
        proposal_id=uuid4(),
        finding_id=uuid4(),
        organization_id=uuid4(),
        root_cause="test",
        proposed_remediation=remediation_text,
        affected_files=files,
        patches=patches,
        expected_security_effect="test",
        expected_behavior="test",
        test_plan="test",
        rollback_plan="test",
        risk_assessment="test",
    )


class TestSecurityPolicyEnforcement:
    def test_infrastructure_modification_blocked(self):
        """Infrastructure files must never be modified."""
        for path in RemediationPolicy.FORBIDDEN_PATHS:
            proposal = _make_proposal(
                files=[path],
                patches=[PatchSpec(file_path=path, operation="modify", patch_diff="malicious")],
            )
            is_valid, reason = RemediationPolicyValidator.validate(proposal)
            assert is_valid is False, f"Policy bypass for {path}"

    def test_security_control_disabling_blocked(self):
        """Security controls must never be disabled."""
        dangerous_content = [
            "disable authentication",
            "bypass security",
            "remove csrf",
            "turn off cors",
            "skip validation",
        ]
        for content in dangerous_content:
            proposal = _make_proposal(
                patches=[PatchSpec(file_path="app.py", operation="modify", patch_diff=content)],
            )
            is_valid, reason = RemediationPolicyValidator.validate(proposal)
            assert is_valid is False, f"Security control bypass for: {content}"

    def test_excessive_scope_blocked(self):
        """Proposals modifying too many files must be rejected."""
        proposal = _make_proposal(files=[f"file{i}.py" for i in range(20)], patches=[])
        is_valid, reason = RemediationPolicyValidator.validate(proposal)
        assert is_valid is False

    def test_oversized_patch_blocked(self):
        """Patches exceeding size limits must be rejected."""
        huge_diff = "x" * (RemediationPolicy.MAX_TOTAL_PATCH_BYTES + 1000)
        proposal = _make_proposal(
            patches=[PatchSpec(file_path="app.py", operation="modify", patch_diff=huge_diff)]
        )
        is_valid, reason = RemediationPolicyValidator.validate(proposal)
        assert is_valid is False

    def test_sentinelforge_code_protection(self):
        """SentinelForge internal code must never be modified."""
        paths = [
            "sentinelforge/domain/models.py",
            "sentinelforge/remediation/orchestrator.py",
            "sentinelforge/agents/red/agent.py",
        ]
        for path in paths:
            proposal = _make_proposal(
                files=[path],
                patches=[PatchSpec(file_path=path, operation="modify", patch_diff="x = 1")],
            )
            is_valid, reason = RemediationPolicyValidator.validate(proposal)
            assert is_valid is False, f"Sentinelforge code modification allowed for {path}"

    def test_docker_compose_protection(self):
        """Docker compose files must never be modified."""
        proposal = _make_proposal(
            files=["docker-compose.yml"],
            patches=[PatchSpec(file_path="docker-compose.yml", operation="modify", patch_diff="version: '3'")],
        )
        is_valid, reason = RemediationPolicyValidator.validate(proposal)
        assert is_valid is False
