"""SentinelForge Branch 2 — Integration Tests for Remediation Pipeline."""

import os
import tempfile
import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from sentinelforge.remediation.clone_manager import CloneManager
from sentinelforge.remediation.executor import CloneRemediationExecutor
from sentinelforge.remediation.models import (
    ApplicationTarget,
    CloneStatus,
    PatchSpec,
    RemediationBudget,
    RemediationProposal,
    TargetEnvironment,
    TargetType,
    VulnerabilityCategory,
    VulnerabilityConfidence,
    VulnerabilityFinding,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from sentinelforge.remediation.orchestrator import RemediationOrchestrator
from sentinelforge.remediation.policy import RemediationPolicy
from sentinelforge.remediation.retest import VulnerabilityRetestOrchestrator


@pytest.fixture
def clone_manager():
    return CloneManager()


@pytest.fixture
def vulnerable_app_dir(tmp_path):
    """Create a vulnerable Flask app for testing."""
    app_dir = tmp_path / "vulnerable_app"
    app_dir.mkdir()
    (app_dir / "app.py").write_text('''from flask import Flask, request
import sqlite3, os

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    return "Welcome"

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        query = f"SELECT * FROM users WHERE username='"'"'{username}'"'"' AND password='"'"'{password}'"'"'"
        user = conn.execute(query).fetchone()
        if user:
            return "Welcome, " + username
        return "Invalid credentials"
    return "Login page"
''')
    return app_dir


@pytest.fixture
def lab_target(vulnerable_app_dir):
    return ApplicationTarget(
        target_id=uuid4(),
        organization_id=uuid4(),
        name="Vulnerable App",
        target_type=TargetType.DOCKERIZED,
        environment=TargetEnvironment.LAB,
        local_path=str(vulnerable_app_dir),
        authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )


@pytest.fixture
def finding(lab_target):
    return VulnerabilityFinding(
        finding_id=uuid4(),
        organization_id=lab_target.organization_id,
        target_id=lab_target.target_id,
        attack_technique_id="T1190",
        vulnerability_category=VulnerabilityCategory.INJECTION.value,
        affected_component="/login",
        evidence="SQL injection via string formatting in query",
        severity=VulnerabilitySeverity.HIGH,
        confidence=VulnerabilityConfidence.CONFIRMED,
        reproduction_info="POST /login with username=' OR '1'='1 returns 200",
        status=VulnerabilityStatus.OPEN,
    )


@pytest.fixture
def proposal(finding):
    return RemediationProposal(
        proposal_id=uuid4(),
        finding_id=finding.finding_id,
        organization_id=finding.organization_id,
        root_cause="SQL injection via f-string formatting",
        proposed_remediation="Use parameterized queries with ? placeholders",
        affected_files=["app.py"],
        patches=[
            PatchSpec(
                file_path="app.py",
                operation="modify",
                patch_diff='''from flask import Flask, request
import sqlite3, os

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/")
def index():
    return "Welcome"

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        query = "SELECT * FROM users WHERE username=? AND password=?"
        user = conn.execute(query, (username, password)).fetchone()
        if user:
            return "Welcome, " + username
        return "Invalid credentials"
    return "Login page"
''',
            )
        ],
        expected_security_effect="Prevents SQL injection attacks",
        expected_behavior="Login still works with valid credentials",
        test_plan="Test with SQL injection payloads and verify they are blocked",
        rollback_plan="Revert app.py to original version",
        risk_assessment="Low risk - only changes query parameterization",
    )


class TestCloneManagerIntegration:
    def test_full_clone_lifecycle(self, clone_manager, lab_target):
        """Test clone creation, snapshot, modification, rollback, cleanup."""
        clone = clone_manager.create_clone(lab_target)
        assert clone.status == CloneStatus.READY
        assert os.path.exists(clone.filesystem_path)

        snapshot = clone_manager.snapshot_clone(clone)
        assert len(snapshot.file_hashes) > 0

        app_path = os.path.join(clone.filesystem_path, "app.py")
        with open(app_path, "w") as f:
            f.write("MODIFIED CONTENT")

        result = clone_manager.rollback_clone(clone, snapshot, lab_target.local_path)
        assert result is True

        with open(app_path) as f:
            assert "MODIFIED CONTENT" not in f.read()

        clone_manager.cleanup_clone(clone)
        assert not os.path.exists(clone.filesystem_path)


class TestExecutorIntegration:
    def test_execute_valid_proposal(self, clone_manager, lab_target, proposal):
        """Test executor applies valid proposal successfully."""
        executor = CloneRemediationExecutor(clone_manager)
        clone = clone_manager.create_clone(lab_target)

        result = executor.execute(
            proposal=proposal,
            clone=clone,
            original_source_path=lab_target.local_path,
        )

        assert result.changes_applied is True
        assert result.build_passed is True
        clone_manager.cleanup_clone(clone)


class TestOrchestratorIntegration:
    def test_orchestrator_validate_proposal(self):
        """Test orchestrator validates proposals against policy."""
        orchestrator = RemediationOrchestrator()

        valid_proposal = RemediationProposal(
            proposal_id=uuid4(),
            finding_id=uuid4(),
            organization_id=uuid4(),
            root_cause="test",
            proposed_remediation="test",
            affected_files=["app.py"],
            patches=[PatchSpec(file_path="app.py", operation="modify", patch_diff="x = 1")],
            expected_security_effect="test",
            expected_behavior="test",
            test_plan="test",
            rollback_plan="test",
            risk_assessment="test",
        )
        is_valid, reason = orchestrator.validate_proposal(valid_proposal)
        assert is_valid is True

    def test_orchestrator_rejects_bad_proposal(self):
        """Test orchestrator rejects invalid proposals."""
        orchestrator = RemediationOrchestrator()

        bad_proposal = RemediationProposal(
            proposal_id=uuid4(),
            finding_id=uuid4(),
            organization_id=uuid4(),
            root_cause="test",
            proposed_remediation="test",
            affected_files=["app.py"],
            patches=[
                PatchSpec(
                    file_path="app.py",
                    operation="modify",
                    patch_diff="# disable authentication",
                )
            ],
            expected_security_effect="test",
            expected_behavior="test",
            test_plan="test",
            rollback_plan="test",
            risk_assessment="test",
        )
        is_valid, reason = orchestrator.validate_proposal(bad_proposal)
        assert is_valid is False
