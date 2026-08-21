"""SentinelForge Branch 2 — Unit Tests for Clone Manager."""

import os
import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from sentinelforge.remediation.clone_manager import CloneManager
from sentinelforge.remediation.exceptions import CloneCreationFailed, RollbackFailed
from sentinelforge.remediation.models import (
    ApplicationTarget,
    CloneStatus,
    TargetEnvironment,
    TargetType,
)


@pytest.fixture
def clone_manager():
    return CloneManager()


@pytest.fixture
def lab_target(tmp_path):
    """Create a lab target with actual files."""
    app_dir = tmp_path / "vulnerable_app"
    app_dir.mkdir()
    (app_dir / "app.py").write_text(
        'from flask import Flask\napp = Flask(__name__)\n@app.route("/login")\ndef login():\n    return "login"\n'
    )
    (app_dir / "requirements.txt").write_text("flask>=2.3\n")
    return ApplicationTarget(
        target_id=uuid4(),
        organization_id=uuid4(),
        name="Test Vulnerable App",
        target_type=TargetType.DOCKERIZED,
        environment=TargetEnvironment.LAB,
        local_path=str(app_dir),
        authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )


class TestCloneManager:
    def test_create_clone(self, clone_manager, lab_target):
        clone = clone_manager.create_clone(lab_target)
        assert clone.status == CloneStatus.READY
        assert clone.network_isolated is True
        assert clone.original_secrets_excluded is True
        assert clone.filesystem_path is not None
        assert os.path.exists(clone.filesystem_path)
        assert os.path.exists(os.path.join(clone.filesystem_path, "app.py"))
        clone_manager.cleanup_clone(clone)

    def test_create_clone_production_rejected(self, clone_manager, tmp_path):
        app_dir = tmp_path / "prod"
        app_dir.mkdir()
        (app_dir / "app.py").write_text("x = 1")
        target = ApplicationTarget(
            target_id=uuid4(),
            organization_id=uuid4(),
            name="Production App",
            target_type=TargetType.DOCKERIZED,
            environment=TargetEnvironment.PRODUCTION,
            local_path=str(app_dir),
            authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )
        with pytest.raises(CloneCreationFailed, match="Production targets cannot enter"):
            clone_manager.create_clone(target)

    def test_create_clone_inactive_target(self, clone_manager, lab_target):
        lab_target.is_active = False
        with pytest.raises(CloneCreationFailed, match="not active"):
            clone_manager.create_clone(lab_target)

    def test_snapshot_clone(self, clone_manager, lab_target):
        clone = clone_manager.create_clone(lab_target)
        snapshot = clone_manager.snapshot_clone(clone)
        assert snapshot.version == clone.current_version
        assert snapshot.snapshot_type == "pre_remediation"
        assert len(snapshot.file_hashes) > 0
        clone_manager.cleanup_clone(clone)

    def test_rollback_clone(self, clone_manager, lab_target):
        clone = clone_manager.create_clone(lab_target)
        snapshot = clone_manager.snapshot_clone(clone)
        with open(os.path.join(clone.filesystem_path, "app.py"), "w") as f:
            f.write("MODIFIED")
        result = clone_manager.rollback_clone(clone, snapshot, lab_target.local_path)
        assert result is True
        with open(os.path.join(clone.filesystem_path, "app.py")) as f:
            content = f.read()
        assert "MODIFIED" not in content
        clone_manager.cleanup_clone(clone)

    def test_cleanup_clone(self, clone_manager, lab_target):
        clone = clone_manager.create_clone(lab_target)
        path = clone.filesystem_path
        assert os.path.exists(path)
        clone_manager.cleanup_clone(clone)
        assert not os.path.exists(path)
        assert clone.status == CloneStatus.CLEANED_UP

    def test_health_check(self, clone_manager, lab_target):
        clone = clone_manager.create_clone(lab_target)
        assert clone_manager.health_check(clone) is True
        clone_manager.cleanup_clone(clone)
        assert clone_manager.health_check(clone) is False

    def test_hash_directory_deterministic(self, clone_manager, tmp_path):
        (tmp_path / "file.txt").write_text("content")
        h1 = clone_manager._hash_directory(str(tmp_path))
        h2 = clone_manager._hash_directory(str(tmp_path))
        assert h1 == h2
