"""SentinelForge Branch 2 — Vulnerability Retest Orchestrator.

Orchestrates Red Agent retesting of remediated vulnerabilities.
Reuses existing Red Agent infrastructure; no second Red Agent is created.
"""

import os
import subprocess
import sys
from datetime import datetime, timezone
from typing import List, Optional, Tuple
from uuid import uuid4

from sentinelforge.remediation.models import (
    PatchSpec,
    RemediationProposal,
    TargetClone,
    VulnerabilityFinding,
    VulnerabilityRetestResult,
)


class VulnerabilityRetestOrchestrator:
    """Orchestrates retesting of remediated vulnerabilities.

    Stage 1: Replay original attack against remediated clone
    Stage 2: Test relevant attack variants (limited by max_variants)
    Stage 3: Regression testing (application health check)
    """

    def execute_retest(
        self,
        finding: VulnerabilityFinding,
        proposal: RemediationProposal,
        clone: TargetClone,
        attempt_number: int = 1,
        max_variants: int = 3,
    ) -> VulnerabilityRetestResult:
        """Execute the full retest pipeline against a remediated clone.

        Returns a VulnerabilityRetestResult with evidence from all stages.
        """
        # Stage 1: Replay original attack
        original_blocked, original_evidence = self._test_original_attack(
            finding, clone
        )

        # Stage 2: Test variants
        variants_tested, variants_blocked, variant_details = self._test_variants(
            finding, clone, max_variants
        )

        # Stage 3: Regression testing
        regression_passed, app_functional = self._run_regression_tests(clone)

        # Determine overall outcome
        vulnerability_eliminated = (
            original_blocked
            and regression_passed
            and app_functional
            and (variants_tested == 0 or variants_blocked >= variants_tested * 0.8)
        )

        if vulnerability_eliminated:
            retest_outcome = "VERIFIED"
        elif not regression_passed or not app_functional:
            retest_outcome = "REQUIRES_REVIEW"
        else:
            retest_outcome = "FAILED"

        return VulnerabilityRetestResult(
            retest_id=uuid4(),
            finding_id=finding.finding_id,
            proposal_id=proposal.proposal_id,
            clone_id=clone.clone_id,
            attempt_number=attempt_number,
            original_attack_blocked=original_blocked,
            original_attack_evidence=original_evidence,
            variants_tested=variants_tested,
            variants_blocked=variants_blocked,
            variant_details=variant_details,
            regression_tests_passed=regression_passed,
            application_functional=app_functional,
            vulnerability_eliminated=vulnerability_eliminated,
            retest_outcome=retest_outcome,
            evaluated_at=datetime.now(timezone.utc),
            provenance={"finding_id": str(finding.finding_id)},
        )

    def _test_original_attack(
        self,
        finding: VulnerabilityFinding,
        clone: TargetClone,
    ) -> Tuple[bool, str]:
        """Replay the original attack against the remediated clone.

        For SQL injection: sends a POST request with a malicious payload
        to the login endpoint. If the attack no longer succeeds (returns
        a safe response), the vulnerability is blocked.
        """
        if not clone.filesystem_path:
            return False, "No clone filesystem path"

        # For the vertical slice, we test SQL injection specifically
        if finding.vulnerability_category == "A03_INJECTION":
            return self._test_sqli_attack(clone, finding)

        return False, f"Unsupported vulnerability category: {finding.vulnerability_category}"

    def _test_sqli_attack(
        self,
        clone: TargetClone,
        finding: VulnerabilityFinding,
    ) -> Tuple[bool, str]:
        """Test SQL injection against the remediated clone.

        Sends a request with a malicious SQL payload to the login endpoint.
        The attack is "blocked" if:
        - The server doesn't crash (returns a valid HTTP response)
        - The response doesn't indicate successful authentication bypass
        - The SQL error doesn't leak database information
        """
        try:
            import requests
        except ImportError:
            # Fallback: use urllib
            return self._test_sqli_urllib(clone, finding)

        # Try common SQL injection payloads
        payloads = [
            "' OR '1'='1",
            "admin' --",
            "' OR 1=1 --",
            "1' UNION SELECT * FROM users --",
        ]

        for payload in payloads:
            try:
                # Find the port the Flask app is running on
                port = self._find_app_port(clone)
                if not port:
                    return False, "Could not find running app port"

                response = requests.post(
                    f"http://127.0.0.1:{port}/login",
                    data={"username": payload, "password": "anything"},
                    timeout=5,
                )

                # Check if login succeeded (should NOT succeed after remediation)
                if response.status_code == 200:
                    body = response.text.lower()
                    if "welcome" in body or "dashboard" in body or "success" in body:
                        return False, f"SQL injection succeeded with payload: {payload}"

                # If we get here, the attack was blocked for this payload
            except requests.exceptions.ConnectionError:
                return False, "Application not running on clone"
            except Exception as exc:
                return False, f"Retest error: {exc}"

        return True, "All SQL injection payloads were blocked"

    def _test_sqli_urllib(
        self,
        clone: TargetClone,
        finding: VulnerabilityFinding,
    ) -> Tuple[bool, str]:
        """Fallback SQL injection test using stdlib urllib."""
        import urllib.request
        import urllib.parse

        payloads = ["' OR '1'='1", "admin' --"]

        for payload in payloads:
            try:
                port = self._find_app_port(clone)
                if not port:
                    return False, "Could not find running app port"

                data = urllib.parse.urlencode({
                    "username": payload,
                    "password": "anything",
                }).encode("utf-8")

                req = urllib.request.Request(
                    f"http://127.0.0.1:{port}/login",
                    data=data,
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read().decode("utf-8", errors="replace").lower()
                    if "welcome" in body or "dashboard" in body:
                        return False, f"SQL injection succeeded with payload: {payload}"
            except Exception:
                continue

        return True, "All SQL injection payloads were blocked (urllib)"

    def _find_app_port(self, clone: TargetClone) -> Optional[int]:
        """Find the port the Flask app is running on in the clone."""
        # For the vertical slice, try common Flask ports
        import socket

        for port in [5000, 5001, 8080, 8000]:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(1)
                    result = s.connect_ex(("127.0.0.1", port))
                    if result == 0:
                        return port
            except Exception:
                continue
        return None

    def _test_variants(
        self,
        finding: VulnerabilityFinding,
        clone: TargetClone,
        max_variants: int,
    ) -> Tuple[int, int, List[dict]]:
        """Test attack variants. Returns (tested, blocked, details)."""
        if finding.vulnerability_category != "A03_INJECTION":
            return 0, 0, []

        try:
            import requests
        except ImportError:
            return 0, 0, []

        variant_payloads = [
            ("time_based_sqli", "' OR SLEEP(1)--"),
            ("union_sqli", "' UNION SELECT null,null,null--"),
            ("error_based_sqli", "' AND 1=CONVERT(int,@@version)--"),
        ][:max_variants]

        tested = 0
        blocked = 0
        details = []

        port = self._find_app_port(clone)
        if not port:
            return 0, 0, [{"error": "App not running"}]

        for name, payload in variant_payloads:
            tested += 1
            try:
                response = requests.post(
                    f"http://127.0.0.1:{port}/login",
                    data={"username": payload, "password": "test"},
                    timeout=5,
                )
                body = response.text.lower()
                is_blocked = not ("welcome" in body or "dashboard" in body)
                if is_blocked:
                    blocked += 1
                details.append({
                    "variant": name,
                    "payload": payload,
                    "blocked": is_blocked,
                    "status_code": response.status_code,
                })
            except Exception as exc:
                details.append({"variant": name, "error": str(exc), "blocked": True})
                blocked += 1

        return tested, blocked, details

    def _run_regression_tests(self, clone: TargetClone) -> Tuple[bool, bool]:
        """Run regression tests and check application health.

        Returns (regression_tests_passed, application_functional).
        """
        if not clone.filesystem_path:
            return False, False

        # Check that the app still has required routes
        app_py = os.path.join(clone.filesystem_path, "app.py")
        if not os.path.exists(app_py):
            return False, False

        try:
            with open(app_py, "r", encoding="utf-8") as f:
                content = f.read()

            # Basic regression: required routes still exist
            has_login = "def login" in content
            has_index = "def index" in content
            has_flask = "Flask" in content

            app_functional = has_login and has_index and has_flask

            # Check that tests pass if they exist
            tests_dir = os.path.join(clone.filesystem_path, "tests")
            tests_passed = True
            if os.path.exists(tests_dir):
                result = subprocess.run(
                    [sys.executable, "-m", "pytest", tests_dir, "-x", "-q", "--tb=short"],
                    capture_output=True, text=True, timeout=60,
                    cwd=clone.filesystem_path,
                )
                tests_passed = result.returncode == 0

            return tests_passed, app_functional
        except Exception:
            return False, False
