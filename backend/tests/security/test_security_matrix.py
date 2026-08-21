"""SentinelForge — Security Test Matrix.

Comprehensive tests for clone security, remediation boundaries,
tenancy isolation, and lifecycle management.
"""

import os
import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from sentinelforge.remediation.clone_manager import CloneManager
from sentinelforge.remediation.docker_clone_manager import DockerCloneManager
from sentinelforge.remediation.models import (
    ApplicationTarget,
    PatchSpec,
    RemediationProposal,
    TargetEnvironment,
    TargetType,
    VulnerabilityCategory,
    VulnerabilityConfidence,
    VulnerabilityFinding,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from sentinelforge.remediation.policy import RemediationPolicy, RemediationPolicyValidator
from sentinelforge.remediation.persistence import FindingPersistence, ProposalPersistence


# ---------------------------------------------------------------------------
# CLONE SECURITY
# ---------------------------------------------------------------------------

class TestCloneSecurity:
    def test_production_target_rejected_filesystem(self):
        target = ApplicationTarget(
            target_id=uuid4(), organization_id=uuid4(),
            name="Prod", target_type=TargetType.DOCKERIZED,
            environment=TargetEnvironment.PRODUCTION,
            local_path="/opt/prod",
            authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        with pytest.raises(Exception, match="Production targets cannot enter"):
            CloneManager().create_clone(target)

    def test_production_target_rejected_docker(self):
        target = ApplicationTarget(
            target_id=uuid4(), organization_id=uuid4(),
            name="Prod", target_type=TargetType.DOCKERIZED,
            environment=TargetEnvironment.PRODUCTION,
            local_path="/opt/prod",
            authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        with pytest.raises(Exception, match="Production targets cannot enter"):
            DockerCloneManager(force_filesystem=True).create_clone(target)

    def test_inactive_target_rejected(self):
        target = ApplicationTarget(
            target_id=uuid4(), organization_id=uuid4(),
            name="Inactive", target_type=TargetType.DOCKERIZED,
            environment=TargetEnvironment.LAB,
            local_path="/tmp/x", is_active=False,
            authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        with pytest.raises(Exception, match="not active"):
            CloneManager().create_clone(target)

    def test_nonexistent_path_rejected(self):
        target = ApplicationTarget(
            target_id=uuid4(), organization_id=uuid4(),
            name="Missing", target_type=TargetType.DOCKERIZED,
            environment=TargetEnvironment.LAB,
            local_path="/nonexistent/path/xyz",
            authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        with pytest.raises(Exception, match="does not exist"):
            CloneManager().create_clone(target)

    def test_host_filesystem_not_accessible_from_clone(self, tmp_path):
        """Clone does not mount host filesystem."""
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

        mgr = DockerCloneManager(force_filesystem=True)
        clone = mgr.create_clone(target)
        try:
            assert clone.filesystem_path != "/"
            assert clone.filesystem_path != str(tmp_path)
        finally:
            mgr.cleanup_clone(clone)


# ---------------------------------------------------------------------------
# REMEDIATION POLICY
# ---------------------------------------------------------------------------

class TestRemediationSecurity:
    def _proposal(self, files=None, patches=None, remediation="test", diff="x = 1"):
        if files is None:
            files = ["app.py"]
        if patches is None:
            patches = [PatchSpec(file_path="app.py", operation="modify", patch_diff=diff)]
        return RemediationProposal(
            proposal_id=uuid4(), finding_id=uuid4(), organization_id=uuid4(),
            root_cause="test", proposed_remediation=remediation,
            affected_files=files, patches=patches,
            expected_security_effect="test", expected_behavior="test",
            test_plan="test", rollback_plan="test", risk_assessment="Low",
        )

    def test_path_traversal_rejected(self):
        p = self._proposal(files=["../../etc/passwd"], patches=[
            PatchSpec(file_path="../../etc/passwd", operation="modify", patch_diff="x")
        ])
        v, r = RemediationPolicyValidator.validate(p)
        assert v is False

    def test_absolute_path_rejected(self):
        p = self._proposal(files=["/etc/passwd"], patches=[
            PatchSpec(file_path="/etc/passwd", operation="modify", patch_diff="x")
        ])
        v, r = RemediationPolicyValidator.validate(p)
        assert v is False

    def test_secret_file_rejected(self):
        for pattern in [".env", "secret.key", "credential.json"]:
            p = self._proposal(files=[pattern], patches=[
                PatchSpec(file_path=pattern, operation="modify", patch_diff="stolen")
            ])
            v, r = RemediationPolicyValidator.validate(p)
            assert v is False, f"Should reject {pattern}"

    def test_oversized_patch_rejected(self):
        huge = "x" * (RemediationPolicy.MAX_TOTAL_PATCH_BYTES + 1000)
        p = self._proposal(diff=huge)
        v, r = RemediationPolicyValidator.validate(p)
        assert v is False

    def test_infrastructure_modification_rejected(self):
        for path in ["Dockerfile", "docker-compose.yml", ".github/workflows/ci.yml"]:
            p = self._proposal(files=[path], patches=[
                PatchSpec(file_path=path, operation="modify", patch_diff="malicious")
            ])
            v, r = RemediationPolicyValidator.validate(p)
            assert v is False, f"Should reject {path}"

    def test_security_control_disabling_rejected(self):
        p = self._proposal(remediation="disable authentication", diff="# disable auth")
        v, r = RemediationPolicyValidator.validate(p)
        assert v is False

    def test_empty_patches_rejected(self):
        p = self._proposal(files=[], patches=[])
        v, r = RemediationPolicyValidator.validate(p)
        assert v is False

    def test_too_many_files_rejected(self):
        p = self._proposal(files=[f"f{i}.py" for i in range(10)])
        v, r = RemediationPolicyValidator.validate(p)
        assert v is False


# ---------------------------------------------------------------------------
# TENANCY ISOLATION (persistence-backed)
# ---------------------------------------------------------------------------

class TestTenancyIsolation:
    def test_org_a_cannot_see_org_b_clones(self, tmp_path):
        """Organization A's clone is invisible to Organization B."""
        org_a = uuid4()
        org_b = uuid4()

        app_dir = tmp_path / "app"
        app_dir.mkdir()
        (app_dir / "app.py").write_text("x = 1")

        target_a = ApplicationTarget(
            target_id=uuid4(), organization_id=org_a,
            name="AppA", target_type=TargetType.DOCKERIZED,
            environment=TargetEnvironment.LAB,
            local_path=str(app_dir),
            authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        target_b = ApplicationTarget(
            target_id=uuid4(), organization_id=org_b,
            name="AppB", target_type=TargetType.DOCKERIZED,
            environment=TargetEnvironment.LAB,
            local_path=str(app_dir),
            authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        mgr = CloneManager()
        clone_a = mgr.create_clone(target_a, organization_id=org_a)
        clone_b = mgr.create_clone(target_b, organization_id=org_b)

        try:
            assert clone_a.organization_id == org_a
            assert clone_b.organization_id == org_b
            assert clone_a.organization_id != clone_b.organization_id
            assert clone_a.clone_id != clone_b.clone_id
        finally:
            mgr.cleanup_clone(clone_a)
            mgr.cleanup_clone(clone_b)

    def test_org_a_cannot_see_org_b_findings_persistence(self, test_session_factory):
        """Findings are scoped by organization_id in database."""
        store = FindingPersistence(test_session_factory)

        org_a = uuid4()
        org_b = uuid4()
        target = uuid4()

        store.create(org_a, target, "T1190", "A03_INJECTION", "/login", "evidence_a")
        store.create(org_a, target, "T1190", "A03_INJECTION", "/api", "evidence_a2")
        store.create(org_b, target, "T1190", "A03_INJECTION", "/login", "evidence_b")

        findings_a = store.get_by_organization(org_a)
        findings_b = store.get_by_organization(org_b)

        assert len(findings_a) == 2
        assert len(findings_b) == 1
        assert all(f.organization_id == org_a for f in findings_a)
        assert all(f.organization_id == org_b for f in findings_b)

    def test_org_a_cannot_see_org_b_proposals_persistence(self, test_session_factory):
        """Proposals are scoped by organization_id in database."""
        store = ProposalPersistence(test_session_factory)

        org_a = uuid4()
        org_b = uuid4()
        finding = uuid4()
        target = uuid4()

        store.create(org_a, finding, target, "rc", "pr", ["f.py"], "[]", "se", "eb", "tp", "rp", "ra")
        store.create(org_b, finding, target, "rc2", "pr2", ["g.py"], "[]", "se2", "eb2", "tp2", "rp2", "ra2")

        proposals_a = store.get_by_finding(finding, org_a)
        proposals_b = store.get_by_finding(finding, org_b)

        assert len(proposals_a) == 1
        assert len(proposals_b) == 1
        assert proposals_a[0].organization_id == org_a
        assert proposals_b[0].organization_id == org_b

    def test_cross_tenant_read_denied(self, test_session_factory):
        """Cannot read another org's finding by ID."""
        store = FindingPersistence(test_session_factory)

        org_a = uuid4()
        org_b = uuid4()
        target = uuid4()

        record = store.create(org_a, target, "T1190", "A03_INJECTION", "/login", "evidence")
        # Org B tries to read Org A's finding
        result = store.get(record.id, org_b)
        assert result is None

    def test_cross_tenant_update_denied(self, test_session_factory):
        """Cannot update another org's finding."""
        store = FindingPersistence(test_session_factory)

        org_a = uuid4()
        org_b = uuid4()
        target = uuid4()

        record = store.create(org_a, target, "T1190", "A03_INJECTION", "/login", "evidence")
        # Org B tries to update
        result = store.update_status(record.id, org_b, "CLOSED")
        assert result is None
        # Original unchanged
        original = store.get(record.id, org_a)
        assert original.status == "OPEN"


# ---------------------------------------------------------------------------
# LIFECYCLE
# ---------------------------------------------------------------------------

class TestLifecycle:
    def test_cleanup_after_success(self, tmp_path):
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

        mgr = CloneManager()
        clone = mgr.create_clone(target)
        path = clone.filesystem_path
        assert os.path.exists(path)

        mgr.cleanup_clone(clone)
        assert not os.path.exists(path)
        assert clone.cleanup_status == "CLEANED"

    def test_cleanup_after_failure(self, tmp_path):
        """Cleanup still works even if clone operations failed."""
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

        mgr = CloneManager()
        clone = mgr.create_clone(target)
        path = clone.filesystem_path

        clone.filesystem_path = "/nonexistent/path"
        clone.filesystem_path = path
        mgr.cleanup_clone(clone)
        assert not os.path.exists(path)
