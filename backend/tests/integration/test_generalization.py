"""SentinelForge — E2E Generalization Test.

Proves that the same architecture handles TWO different vulnerable applications.
Application A: vulnerable_app (POST /login, username-based SQLi)
Application B: vulnerable_app_b (POST /authenticate, email-based SQLi)

Classification: MOCK-VERIFIED
"""

import os
import pytest
from datetime import datetime, timezone, timedelta
from uuid import uuid4

from sentinelforge.remediation.bridge import ExecutionEvidence, VulnerabilityBridge
from sentinelforge.remediation.clone_manager import CloneManager
from sentinelforge.remediation.docker_clone_manager import DockerCloneManager
from sentinelforge.remediation.executor import CloneRemediationExecutor
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
from sentinelforge.remediation.orchestrator import RemediationOrchestrator


# ---------------------------------------------------------------------------
# Application A: Login form (POST /login, username field)
# ---------------------------------------------------------------------------

APP_A_VULNERABLE = '''from flask import Flask, request, session, redirect
import sqlite3, os
app = Flask(__name__)
app.secret_key = "key-a"
DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")
def get_db():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; return conn
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
        try: user = conn.execute(query).fetchone()
        except: user = None
        if user: return "Welcome, " + user["username"]
        return "Invalid"
    return "Login page"
@app.route("/health")
def health(): return "ok"
'''

APP_A_REMEDIATED = '''from flask import Flask, request, session, redirect
import sqlite3, os
app = Flask(__name__)
app.secret_key = "key-a"
DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")
def get_db():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; return conn
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        conn = get_db()
        query = "SELECT * FROM users WHERE username=? AND password=?"
        try: user = conn.execute(query, (username, password)).fetchone()
        except: user = None
        if user: return "Welcome, " + user["username"]
        return "Invalid"
    return "Login page"
@app.route("/health")
def health(): return "ok"
'''


# ---------------------------------------------------------------------------
# Application B: Auth service (POST /authenticate, email field, JSON)
# ---------------------------------------------------------------------------

APP_B_VULNERABLE = '''from flask import Flask, request, jsonify
import sqlite3, os
app = Flask(__name__)
app.secret_key = "key-b"
DB_PATH = os.path.join(os.path.dirname(__file__), "auth.db")
def get_db():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; return conn
@app.route("/authenticate", methods=["POST"])
def authenticate():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")
    if not email or not password:
        return jsonify({"error": "required"}), 400
    conn = get_db()
    query = f"SELECT * FROM accounts WHERE email='{email}' AND password='{password}'"
    try: account = conn.execute(query).fetchone()
    except: account = None
    if account:
        return jsonify({"status": "authenticated", "name": account["display_name"]})
    return jsonify({"error": "Invalid"}), 401
@app.route("/health")
def health(): return "ok"
'''

APP_B_REMEDIATED = '''from flask import Flask, request, jsonify
import sqlite3, os
app = Flask(__name__)
app.secret_key = "key-b"
DB_PATH = os.path.join(os.path.dirname(__file__), "auth.db")
def get_db():
    conn = sqlite3.connect(DB_PATH); conn.row_factory = sqlite3.Row; return conn
@app.route("/authenticate", methods=["POST"])
def authenticate():
    data = request.get_json(silent=True) or {}
    email = data.get("email", "")
    password = data.get("password", "")
    if not email or not password:
        return jsonify({"error": "required"}), 400
    conn = get_db()
    query = "SELECT * FROM accounts WHERE email=? AND password=?"
    try: account = conn.execute(query, (email, password)).fetchone()
    except: account = None
    if account:
        return jsonify({"status": "authenticated", "name": account["display_name"]})
    return jsonify({"error": "Invalid"}), 401
@app.route("/health")
def health(): return "ok"
'''


def _make_app(tmp_path, name, content):
    app_dir = tmp_path / name
    app_dir.mkdir(exist_ok=True)
    (app_dir / "app.py").write_text(content)
    return app_dir


def _make_target(tmp_path, name, content, port=5000):
    app_dir = _make_app(tmp_path, name, content)
    return ApplicationTarget(
        target_id=uuid4(),
        organization_id=uuid4(),
        name=f"App {name}",
        target_type=TargetType.DOCKERIZED,
        environment=TargetEnvironment.LAB,
        local_path=str(app_dir),
        authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )


# ---------------------------------------------------------------------------
# TEST: Application A (original login form)
# ---------------------------------------------------------------------------

class TestAppA:
    def test_sqli_evidence_creates_finding(self, tmp_path):
        """Application A: SQL injection evidence creates a VulnerabilityFinding."""
        target = _make_target(tmp_path, "app_a", APP_A_VULNERABLE)

        evidence = ExecutionEvidence(
            exit_code=0,
            stdout="Welcome, admin\n",
            stderr="",
            command_executed="POST /login username=admin' OR '1'='1 password=anything",
            technique_id="T1190",
        )

        bridge = VulnerabilityBridge()
        finding = bridge.evaluate_execution(evidence=evidence, target=target)

        assert finding is not None
        assert finding.vulnerability_category == VulnerabilityCategory.INJECTION.value
        assert finding.confidence == VulnerabilityConfidence.CONFIRMED

    def test_remediation_applied_to_clone(self, tmp_path):
        """Application A: Remediation applied only to clone, not original."""
        target = _make_target(tmp_path, "app_a", APP_A_VULNERABLE)
        original_path = os.path.join(target.local_path, "app.py")

        proposal = RemediationProposal(
            proposal_id=uuid4(),
            finding_id=uuid4(),
            organization_id=target.organization_id,
            root_cause="SQL injection via f-string",
            proposed_remediation="Use parameterized queries",
            affected_files=["app.py"],
            patches=[PatchSpec(file_path="app.py", operation="modify", patch_diff=APP_A_REMEDIATED)],
            expected_security_effect="Prevents SQLi",
            expected_behavior="Login works",
            test_plan="Test with payloads",
            rollback_plan="Revert",
            risk_assessment="Low",
        )

        orchestrator = RemediationOrchestrator()
        is_valid, _ = orchestrator.validate_proposal(proposal)
        assert is_valid is True

        clone_manager = CloneManager()
        executor = CloneRemediationExecutor(clone_manager)
        clone = clone_manager.create_clone(target)

        try:
            result = executor.execute(proposal=proposal, clone=clone, original_source_path=target.local_path)
            assert result.build_passed is True
            assert result.changes_applied is True

            # Clone has remediated code
            with open(os.path.join(clone.filesystem_path, "app.py")) as f:
                clone_content = f.read()
            assert "WHERE username=? AND password=?" in clone_content

            # Original still vulnerable
            with open(original_path) as f:
                orig_content = f.read()
            assert "f\"SELECT" in orig_content or "{username}" in orig_content
        finally:
            clone_manager.cleanup_clone(clone)


# ---------------------------------------------------------------------------
# TEST: Application B (auth service, different structure)
# ---------------------------------------------------------------------------

class TestAppB:
    def test_sqli_evidence_creates_finding(self, tmp_path):
        """Application B: SQL injection in different endpoint creates finding."""
        target = _make_target(tmp_path, "app_b", APP_B_VULNERABLE)

        evidence = ExecutionEvidence(
            exit_code=0,
            stdout='{"status": "authenticated", "name": "Alice"}\n',
            stderr="",
            command_executed='POST /authenticate email=alice@example.com\' OR \'1\'=\'1 password=anything',
            technique_id="T1190",
        )

        bridge = VulnerabilityBridge()
        finding = bridge.evaluate_execution(evidence=evidence, target=target)

        assert finding is not None
        assert finding.vulnerability_category == VulnerabilityCategory.INJECTION.value
        assert "/authenticate" in finding.affected_component or "unknown" in finding.affected_component

    def test_remediation_applied_to_clone(self, tmp_path):
        """Application B: Remediation applied only to clone, not original."""
        target = _make_target(tmp_path, "app_b", APP_B_VULNERABLE)
        original_path = os.path.join(target.local_path, "app.py")

        proposal = RemediationProposal(
            proposal_id=uuid4(),
            finding_id=uuid4(),
            organization_id=target.organization_id,
            root_cause="SQL injection in /authenticate via f-string",
            proposed_remediation="Use parameterized queries with ? placeholders",
            affected_files=["app.py"],
            patches=[PatchSpec(file_path="app.py", operation="modify", patch_diff=APP_B_REMEDIATED)],
            expected_security_effect="Prevents SQLi in /authenticate",
            expected_behavior="Authentication still works",
            test_plan="Test with SQL payloads",
            rollback_plan="Revert file",
            risk_assessment="Low",
        )

        orchestrator = RemediationOrchestrator()
        is_valid, _ = orchestrator.validate_proposal(proposal)
        assert is_valid is True

        clone_manager = CloneManager()
        executor = CloneRemediationExecutor(clone_manager)
        clone = clone_manager.create_clone(target)

        try:
            result = executor.execute(proposal=proposal, clone=clone, original_source_path=target.local_path)
            assert result.build_passed is True

            # Clone remediated
            with open(os.path.join(clone.filesystem_path, "app.py")) as f:
                clone_content = f.read()
            assert "WHERE email=? AND password=?" in clone_content

            # Original still vulnerable
            with open(original_path) as f:
                orig_content = f.read()
            assert "f\"SELECT" in orig_content or "{email}" in orig_content
        finally:
            clone_manager.cleanup_clone(clone)


# ---------------------------------------------------------------------------
# TEST: Generalization (same architecture, different apps)
# ---------------------------------------------------------------------------

class TestGeneralization:
    def test_same_bridge_handles_both_apps(self, tmp_path):
        """The same VulnerabilityBridge handles both applications."""
        bridge = VulnerabilityBridge()

        # App A: login form
        target_a = _make_target(tmp_path, "a", APP_A_VULNERABLE)
        evidence_a = ExecutionEvidence(
            exit_code=0, stdout="Welcome, admin\n", stderr="",
            command_executed="POST /login username=admin' OR '1'='1 password=x",
            technique_id="T1190",
        )
        finding_a = bridge.evaluate_execution(evidence=evidence_a, target=target_a)
        assert finding_a is not None

        # App B: auth service
        target_b = _make_target(tmp_path, "b", APP_B_VULNERABLE)
        evidence_b = ExecutionEvidence(
            exit_code=0, stdout='{"status": "authenticated"}\n', stderr="",
            command_executed="POST /authenticate email=alice@example.com' OR '1'='1 password=x",
            technique_id="T1190",
        )
        finding_b = bridge.evaluate_execution(evidence=evidence_b, target=target_b)
        assert finding_b is not None

        # Both findings from the same bridge
        assert finding_a.finding_id != finding_b.finding_id
        assert finding_a.vulnerability_category == finding_b.vulnerability_category

    def test_same_orchestrator_handles_both_apps(self, tmp_path):
        """The same RemediationOrchestrator handles both applications."""
        orchestrator = RemediationOrchestrator()

        # App A
        target_a = _make_target(tmp_path, "a", APP_A_VULNERABLE)
        proposal_a = RemediationProposal(
            proposal_id=uuid4(), finding_id=uuid4(),
            organization_id=target_a.organization_id,
            root_cause="SQLi", proposed_remediation="Fix",
            affected_files=["app.py"],
            patches=[PatchSpec(file_path="app.py", operation="modify", patch_diff=APP_A_REMEDIATED)],
            expected_security_effect="x", expected_behavior="x",
            test_plan="x", rollback_plan="x", risk_assessment="Low",
        )
        assert orchestrator.validate_proposal(proposal_a)[0] is True

        # App B
        target_b = _make_target(tmp_path, "b", APP_B_VULNERABLE)
        proposal_b = RemediationProposal(
            proposal_id=uuid4(), finding_id=uuid4(),
            organization_id=target_b.organization_id,
            root_cause="SQLi", proposed_remediation="Fix",
            affected_files=["app.py"],
            patches=[PatchSpec(file_path="app.py", operation="modify", patch_diff=APP_B_REMEDIATED)],
            expected_security_effect="x", expected_behavior="x",
            test_plan="x", rollback_plan="x", risk_assessment="Low",
        )
        assert orchestrator.validate_proposal(proposal_b)[0] is True


def _docker_available():
    try:
        import subprocess
        return subprocess.run(["docker", "info"], capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# TEST: Docker clone (when available)
# ---------------------------------------------------------------------------

class TestDockerClone:
    @pytest.mark.skipif(
        not _docker_available(),
        reason="Docker not available",
    )
    def test_docker_clone_backend(self, tmp_path):
        """Docker clone manager creates isolated container."""
        docker_mgr = DockerCloneManager()
        assert docker_mgr.backend == "docker"

        target = _make_target(tmp_path, "docker_app", APP_A_VULNERABLE)
        clone = docker_mgr.create_clone(target)

        try:
            assert clone.docker_container_name is not None
            assert clone.docker_network == DockerCloneManager.NETWORK_NAME
            assert clone.status.value == "READY"
            assert docker_mgr.health_check(clone) is True
        finally:
            docker_mgr.cleanup_clone(clone)

    def test_filesystem_fallback(self, tmp_path):
        """Filesystem clone works when Docker is forced off."""
        mgr = DockerCloneManager(force_filesystem=True)
        assert mgr.backend == "filesystem"

        target = _make_target(tmp_path, "fs_app", APP_A_VULNERABLE)
        clone = mgr.create_clone(target)

        try:
            assert clone.filesystem_path is not None
            assert os.path.exists(clone.filesystem_path)
        finally:
            mgr.cleanup_clone(clone)
