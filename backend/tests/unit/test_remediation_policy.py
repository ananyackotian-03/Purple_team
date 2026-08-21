"""SentinelForge Branch 2 — Unit Tests for Remediation Policy."""

import pytest
from uuid import uuid4

from sentinelforge.remediation.models import PatchSpec, RemediationProposal
from sentinelforge.remediation.policy import RemediationPolicy, RemediationPolicyValidator


class TestRemediationPolicy:
    def test_constants(self):
        assert RemediationPolicy.MAX_FILES_CHANGED == 5
        assert RemediationPolicy.MAX_PATCH_SIZE_BYTES == 16384
        assert RemediationPolicy.MAX_TOTAL_PATCH_BYTES == 65536

    def test_forbidden_paths(self):
        assert "Dockerfile" in RemediationPolicy.FORBIDDEN_PATHS
        assert "docker-compose.yml" in RemediationPolicy.FORBIDDEN_PATHS
        assert ".github/" in RemediationPolicy.FORBIDDEN_PATHS

    def test_sentinelforge_protection(self):
        assert "sentinelforge/" in RemediationPolicy.FORBIDDEN_PATHS


def _make_proposal(files=None, patches=None):
    if files is None:
        files = ["app.py"]
    if patches is None:
        patches = [PatchSpec(file_path="app.py", operation="modify", patch_diff="x = 1")]
    return RemediationProposal(
        proposal_id=uuid4(),
        finding_id=uuid4(),
        organization_id=uuid4(),
        root_cause="test",
        proposed_remediation="test",
        affected_files=files,
        patches=patches,
        expected_security_effect="test",
        expected_behavior="test",
        test_plan="test",
        rollback_plan="test",
        risk_assessment="test",
    )


class TestRemediationPolicyValidator:
    def test_valid_proposal(self):
        proposal = _make_proposal()
        is_valid, reason = RemediationPolicyValidator.validate(proposal)
        assert is_valid is True
        assert "policy constraints" in reason.lower() or is_valid

    def test_too_many_files(self):
        proposal = _make_proposal(files=[f"file{i}.py" for i in range(10)])
        is_valid, reason = RemediationPolicyValidator.validate(proposal)
        assert is_valid is False
        assert "too many files" in reason.lower()

    def test_forbidden_path_dockerfile(self):
        proposal = _make_proposal(
            files=["Dockerfile"],
            patches=[PatchSpec(file_path="Dockerfile", operation="modify", patch_diff="FROM alpine")],
        )
        is_valid, reason = RemediationPolicyValidator.validate(proposal)
        assert is_valid is False
        assert "forbidden" in reason.lower()

    def test_forbidden_path_sentinelforge(self):
        proposal = _make_proposal(
            files=["sentinelforge/domain/models.py"],
            patches=[PatchSpec(file_path="sentinelforge/domain/models.py", operation="modify", patch_diff="x = 1")],
        )
        is_valid, reason = RemediationPolicyValidator.validate(proposal)
        assert is_valid is False
        assert "sentinelforge" in reason.lower()

    def test_patch_too_large(self):
        large_diff = "x" * (RemediationPolicy.MAX_PATCH_SIZE_BYTES + 1)
        proposal = _make_proposal(
            patches=[PatchSpec(file_path="app.py", operation="modify", patch_diff=large_diff)]
        )
        is_valid, reason = RemediationPolicyValidator.validate(proposal)
        assert is_valid is False
        assert "too large" in reason.lower()

    def test_forbidden_content_disable_auth(self):
        proposal = _make_proposal(
            patches=[PatchSpec(file_path="app.py", operation="modify", patch_diff="# disable authentication")],
        )
        is_valid, reason = RemediationPolicyValidator.validate(proposal)
        assert is_valid is False
        assert "forbidden" in reason.lower()

    def test_empty_patches(self):
        proposal = _make_proposal(files=[], patches=[])
        is_valid, reason = RemediationPolicyValidator.validate(proposal)
        assert is_valid is False
        assert "no patches" in reason.lower()
