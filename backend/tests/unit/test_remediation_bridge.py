"""SentinelForge — Unit Tests for VulnerabilityBridge."""

import pytest
from uuid import uuid4
from datetime import datetime, timezone, timedelta

from sentinelforge.remediation.bridge import ExecutionEvidence, VulnerabilityBridge
from sentinelforge.remediation.models import (
    ApplicationTarget,
    TargetEnvironment,
    TargetType,
    VulnerabilityCategory,
    VulnerabilityConfidence,
    VulnerabilitySeverity,
)


@pytest.fixture
def bridge():
    return VulnerabilityBridge()


@pytest.fixture
def lab_target():
    return ApplicationTarget(
        target_id=uuid4(),
        organization_id=uuid4(),
        name="Test App",
        target_type=TargetType.DOCKERIZED,
        environment=TargetEnvironment.LAB,
        local_path="/tmp/test",
        authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )


@pytest.fixture
def prod_target():
    return ApplicationTarget(
        target_id=uuid4(),
        organization_id=uuid4(),
        name="Prod App",
        target_type=TargetType.DOCKERIZED,
        environment=TargetEnvironment.PRODUCTION,
        local_path="/opt/prod",
        authorization_expiry=datetime.now(timezone.utc) + timedelta(hours=1),
    )


class TestVulnerabilityBridge:
    def test_sqli_bypass_creates_finding(self, bridge, lab_target):
        evidence = ExecutionEvidence(
            exit_code=0,
            stdout="Welcome, admin\n",
            stderr="",
            command_executed="curl -X POST http://localhost:5000/login -d \"username=admin' OR '1'='1&password=any\"",
            technique_id="T1190",
        )
        finding = bridge.evaluate_execution(evidence=evidence, target=lab_target)
        assert finding is not None
        assert finding.vulnerability_category == VulnerabilityCategory.INJECTION.value
        assert finding.confidence == VulnerabilityConfidence.CONFIRMED
        assert finding.severity == VulnerabilitySeverity.HIGH

    def test_sqli_error_creates_probable_finding(self, bridge, lab_target):
        evidence = ExecutionEvidence(
            exit_code=0,
            stdout="",
            stderr="sqlite3.OperationalError: near \"OR\": syntax error",
            command_executed="curl -X POST http://localhost:5000/login -d \"username=admin' OR 1=1--&password=x\"",
            technique_id="T1190",
        )
        finding = bridge.evaluate_execution(evidence=evidence, target=lab_target)
        assert finding is not None
        assert finding.confidence == VulnerabilityConfidence.PROBABLE

    def test_no_attack_no_finding(self, bridge, lab_target):
        evidence = ExecutionEvidence(
            exit_code=0,
            stdout="Login page\n",
            stderr="",
            command_executed="curl http://localhost:5000/login",
            technique_id="T1190",
        )
        finding = bridge.evaluate_execution(evidence=evidence, target=lab_target)
        assert finding is None

    def test_production_no_finding(self, bridge, prod_target):
        evidence = ExecutionEvidence(
            exit_code=0,
            stdout="Welcome, admin\n",
            stderr="",
            command_executed="curl -X POST http://localhost:5000/login -d \"username=admin' OR '1'='1&password=any\"",
            technique_id="T1190",
        )
        finding = bridge.evaluate_execution(evidence=evidence, target=prod_target)
        assert finding is None

    def test_failed_attack_no_finding(self, bridge, lab_target):
        evidence = ExecutionEvidence(
            exit_code=1,
            stdout="",
            stderr="Connection refused",
            command_executed="curl -X POST http://localhost:5000/login -d \"username=admin' OR '1'='1&password=any\"",
            technique_id="T1190",
        )
        finding = bridge.evaluate_execution(evidence=evidence, target=lab_target)
        assert finding is None
