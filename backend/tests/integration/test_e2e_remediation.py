"""SentinelForge Branch 2 — End-to-End Test: Full Remediation Loop."""

import os
import tempfile
import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from sentinelforge.remediation.clone_manager import CloneManager
from sentinelforge.remediation.executor import CloneRemediationExecutor
from sentinelforge.remediation.models import (
    ApplicationTarget,
    PatchSpec,
    RemediationBudget,
    RemediationOutcome,
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
def vulnerable_app(tmp_path):
    """Create a vulnerable Flask app with SQL injection."""
    app_dir = tmp_path / "app"
    app_dir.mkdir()
    (app_dir / "app.py").write_text('''from flask import Flask, request
import sqlite3, os

app = Flask(__name__)
DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")

def get_db():
    return sqlite3.connect(DB_PATH)

@app.route("/")
def index():
    return "Welcome"

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = get_db()
    query = f"SELECT * FROM users WHERE username='"'"'{username}'"'"' AND password='"'"'{password}'"'"'"
    try:
        user = conn.execute(query).fetchone()
    except Exception:
        user = None
    if user:
        return "Welcome, " + username
    return "Invalid"
''')
    return app_dir


class TestEndToEndRemediation:
    def test_full_remediation_loop(self, vulnerable_app):
        """Test the complete Branch 2 remediation pipeline."""
        org_id = uuid4()

        target = ApplicationTarget(
            target_id=uuid4(),
            organization_id=org_id,
            name="Vulnerable Flask App",
            target_type=TargetType.DOCKERIZED,
            environment=TargetEnvironment.LAB,
            local_path=str(vulnerable_app),
            authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        finding = VulnerabilityFinding(
            finding_id=uuid4(),
            organization_id=org_id,
            target_id=target.target_id,
            attack_technique_id="T1190",
            vulnerability_category=VulnerabilityCategory.INJECTION.value,
            affected_component="/login",
            evidence="SQL injection via f-string formatting",
            severity=VulnerabilitySeverity.HIGH,
            confidence=VulnerabilityConfidence.CONFIRMED,
            status=VulnerabilityStatus.OPEN,
            reproduction_info="POST /login with username=' OR '1'='1",
        )

        proposal = RemediationProposal(
            proposal_id=uuid4(),
            finding_id=finding.finding_id,
            organization_id=org_id,
            root_cause="SQL injection via f-string formatting",
            proposed_remediation="Use parameterized queries",
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
    return sqlite3.connect(DB_PATH)

@app.route("/")
def index():
    return "Welcome"

@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = get_db()
    query = "SELECT * FROM users WHERE username=? AND password=?"
    try:
        user = conn.execute(query, (username, password)).fetchone()
    except Exception:
        user = None
    if user:
        return "Welcome, " + username
    return "Invalid"
''',
                )
            ],
            expected_security_effect="Prevents SQL injection",
            expected_behavior="Login works with valid credentials",
            test_plan="Test with SQL payloads",
            rollback_plan="Revert file",
            risk_assessment="Low",
        )

        orchestrator = RemediationOrchestrator()
        is_valid, reason = orchestrator.validate_proposal(proposal)
        assert is_valid is True, f"Proposal validation failed: {reason}"

        clone_manager = CloneManager()
        executor = CloneRemediationExecutor(clone_manager)
        clone = clone_manager.create_clone(target)

        try:
            exec_result = executor.execute(
                proposal=proposal,
                clone=clone,
                original_source_path=target.local_path,
            )

            assert exec_result.build_passed is True, f"Build failed: {exec_result.build_output}"
            assert exec_result.tests_passed is True, f"Tests failed: {exec_result.test_output}"

            remediated_app_path = os.path.join(clone.filesystem_path, "app.py")
            with open(remediated_app_path) as f:
                content = f.read()
            assert "?" in content, "Parameterized query not found"

        finally:
            clone_manager.cleanup_clone(clone)

    def test_policy_blocks_production_target(self):
        """Test that production targets are blocked from remediation."""
        target = ApplicationTarget(
            target_id=uuid4(),
            organization_id=uuid4(),
            name="Production App",
            target_type=TargetType.DOCKERIZED,
            environment=TargetEnvironment.PRODUCTION,
            local_path="/opt/prod",
            authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
        )

        clone_manager = CloneManager()
        with pytest.raises(Exception, match="Production targets cannot enter"):
            clone_manager.create_clone(target)

    def test_policy_blocks_forbidden_files(self):
        """Test that proposals modifying forbidden files are rejected."""
        proposal = RemediationProposal(
            proposal_id=uuid4(),
            finding_id=uuid4(),
            organization_id=uuid4(),
            root_cause="test",
            proposed_remediation="test",
            affected_files=["Dockerfile"],
            patches=[
                PatchSpec(file_path="Dockerfile", operation="modify", patch_diff="FROM alpine")
            ],
            expected_security_effect="test",
            expected_behavior="test",
            test_plan="test",
            rollback_plan="test",
            risk_assessment="test",
        )
        orchestrator = RemediationOrchestrator()
        is_valid, _ = orchestrator.validate_proposal(proposal)
        assert is_valid is False

    def test_budget_enforcement(self):
        """Test that budget limits are enforced."""
        budget = RemediationBudget(max_iterations=2, max_llm_calls=2)
        started_at = datetime.now(timezone.utc)

        assert budget.has_remaining(iteration=1, llm_calls=1, started_at=started_at) is True
        assert budget.has_remaining(iteration=2, llm_calls=1, started_at=started_at) is False
        assert budget.has_remaining(iteration=1, llm_calls=2, started_at=started_at) is False
