"""SentinelForge — Red Agent → VulnerabilityFinding Bridge.

Converts Red Agent execution results into VulnerabilityFinding objects.
This is the deterministic link between Red Agent execution and Branch 2
remediation.

SECURITY ROLE:
- This module NEVER trusts the LLM output for vulnerability classification.
- Findings are based on concrete execution evidence.
- The LLM may provide hypothesis/reasoning, but evidence is deterministic.
"""

import re
from dataclasses import dataclass
from typing import List, Optional
from uuid import uuid4

from sentinelforge.remediation.models import (
    ApplicationTarget,
    TargetEnvironment,
    TargetType,
    VulnerabilityCategory,
    VulnerabilityConfidence,
    VulnerabilityFinding,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)


@dataclass
class ExecutionEvidence:
    """Concrete evidence from a controlled execution."""
    exit_code: int
    stdout: str
    stderr: str
    command_executed: str
    technique_id: str
    execution_time_ms: float = 0.0


# ---------------------------------------------------------------------------
# Deterministic vulnerability indicators
# ---------------------------------------------------------------------------

_SQLI_ERROR_PATTERNS = [
    r"sqlite3\.OperationalError",
    r"SQL syntax.*MySQL",
    r"ORA-\d{5}",
    r"PostgreSQL.*ERROR",
    r"WARNING.*SQLite",
    r"unterminated.*string",
    r"near .* syntax error",
]

_SQLI_SUCCESS_INDICATORS = [
    r"Welcome,\s*\w+",             # Login bypass succeeded
    r"admin.*admin",                # User data leaked
    r"SELECT.*FROM.*users",         # Query reflected
    r"id\s*=\s*\d+.*username",     # Data rows returned
    r"authenticated",               # Auth bypass via JSON response
    r"SELECT.*FROM.*accounts",      # Query reflected (alternate schema)
]


def _check_sql_injection_evidence(evidence: ExecutionEvidence) -> Optional[dict]:
    """Determine if SQL injection was demonstrated by execution evidence.

    Returns a dict with evidence details if confirmed, None otherwise.
    Never returns a finding based on LLM claims alone.
    """
    combined = evidence.stdout + evidence.stderr
    command = evidence.command_executed.lower()

    # Must have executed something that looks like an attack attempt
    attack_patterns = ["'", "or ", "union", "select", "--", ";", "admin"]
    is_attack_attempt = any(p in command.lower() for p in attack_patterns)
    if not is_attack_attempt:
        return None

    # Check for SQL error messages (indicates SQL injection point)
    has_sqli_error = any(
        re.search(pattern, combined, re.IGNORECASE)
        for pattern in _SQLI_ERROR_PATTERNS
    )

    # Check for successful exploitation (login bypass, data leak)
    has_exploitation = any(
        re.search(pattern, combined, re.IGNORECASE)
        for pattern in _SQLI_SUCCESS_INDICATORS
    )

    # Check for authentication bypass (exit code 0 + welcome message when should fail)
    has_bypass = (
        evidence.exit_code == 0
        and ("Welcome" in combined or "dashboard" in combined.lower()
             or "authenticated" in combined.lower())
        and any(malicious in command.lower() for malicious in ["' or", "'or", "union", "--", "1=1"])
    )

    if has_exploitation or has_bypass:
        return {
            "category": VulnerabilityCategory.INJECTION.value,
            "severity": VulnerabilitySeverity.HIGH.value,
            "confidence": VulnerabilityConfidence.CONFIRMED.value,
            "evidence": f"SQL injection confirmed: {combined[:500]}",
            "component": _extract_endpoint(command),
        }

    if has_sqli_error:
        return {
            "category": VulnerabilityCategory.INJECTION.value,
            "severity": VulnerabilitySeverity.MEDIUM.value,
            "confidence": VulnerabilityConfidence.PROBABLE.value,
            "evidence": f"SQL error indicates injection point: {combined[:500]}",
            "component": _extract_endpoint(command),
        }

    return None


def _extract_endpoint(command: str) -> str:
    """Extract the target endpoint from a command string."""
    # Look for URL patterns
    url_match = re.search(r"(https?://\S+|/\w+[\w/?=&]*)", command)
    if url_match:
        return url_match.group(1)
    # Look for curl/wget patterns
    for pattern in [r"curl\s+\S+", r"wget\s+\S+"]:
        m = re.search(pattern, command)
        if m:
            return m.group(0).split()[-1]
    return "/unknown"


def _classify_severity(evidence: dict) -> VulnerabilitySeverity:
    """Classify severity based on evidence, not LLM claims."""
    confidence = evidence.get("confidence", "")
    if confidence == VulnerabilityConfidence.CONFIRMED.value:
        return VulnerabilitySeverity.HIGH
    return VulnerabilitySeverity.MEDIUM


# ---------------------------------------------------------------------------
# Bridge interface
# ---------------------------------------------------------------------------

class VulnerabilityBridge:
    """Converts Red Agent execution evidence into VulnerabilityFinding objects.

    The bridge requires concrete execution evidence. LLM hypotheses are
    recorded as context but never establish findings alone.
    """

    def evaluate_execution(
        self,
        evidence: ExecutionEvidence,
        target: ApplicationTarget,
        llm_hypothesis: Optional[str] = None,
        llm_reasoning: Optional[str] = None,
        exercise_id=None,
        scenario_id=None,
    ) -> Optional[VulnerabilityFinding]:
        """Evaluate execution evidence and create a VulnerabilityFinding if confirmed.

        Args:
            evidence: Concrete execution output from controlled attack.
            target: The application target that was tested.
            llm_hypothesis: Optional LLM hypothesis (for context only).
            llm_reasoning: Optional LLM reasoning (for context only).
            exercise_id: Associated exercise ID.
            scenario_id: Associated scenario ID.

        Returns:
            VulnerabilityFinding if evidence confirms a vulnerability, else None.
        """
        # Production targets must never produce findings for remediation
        if target.environment == TargetEnvironment.PRODUCTION:
            return None

        # Deterministic evidence evaluation
        sqli_evidence = _check_sql_injection_evidence(evidence)

        if sqli_evidence is None:
            return None

        # Build finding based on EVIDENCE, not LLM claims
        finding = VulnerabilityFinding(
            finding_id=uuid4(),
            organization_id=target.organization_id,
            target_id=target.target_id,
            exercise_id=exercise_id,
            scenario_id=scenario_id,
            attack_technique_id=evidence.technique_id,
            vulnerability_category=sqli_evidence["category"],
            affected_component=sqli_evidence["component"],
            evidence=sqli_evidence["evidence"],
            severity=VulnerabilitySeverity(sqli_evidence["severity"]),
            confidence=VulnerabilityConfidence(sqli_evidence["confidence"]),
            root_cause_hypothesis=llm_hypothesis,
            reproduction_info=f"Execute: {evidence.command_executed}",
            status=VulnerabilityStatus.OPEN,
            provenance={
                "bridge": "VulnerabilityBridge",
                "evidence_based": True,
                "llm_hypothesis_used": False,
                "exit_code": evidence.exit_code,
                "technique_id": evidence.technique_id,
            },
        )

        return finding
