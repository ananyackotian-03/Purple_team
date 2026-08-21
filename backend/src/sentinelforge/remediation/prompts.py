"""SentinelForge Branch 2 — LLM Prompt Templates for Remediation Proposals.

Follows the XML-fencing pattern of agents/red/prompts.py.
Provides system and user prompts for structured remediation proposal generation.
"""

import re
from sentinelforge.remediation.models import (
    ApplicationTarget,
    VulnerabilityFinding,
)
from sentinelforge.remediation.policy import RemediationPolicy


def build_remediation_system_prompt() -> str:
    """System prompt for remediation proposal generation."""
    return """You are the SentinelForge Remediation Agent.

Your role is to propose fixes for application vulnerabilities discovered during authorized security testing.

CRITICAL RULES:
- You are an UNTRUSTED proposal generator. You do NOT have execution authority.
- You propose structured JSON remediation proposals. Deterministic infrastructure validates and applies them.
- You MUST NOT propose modifications to infrastructure files (Dockerfile, docker-compose, CI/CD).
- You MUST NOT propose disabling security controls (authentication, CORS, rate limiting).
- You MUST NOT propose removing functionality to hide a vulnerability.
- You MUST NOT propose modifications to sentinelforge code.
- You MUST only propose changes to application source code files.
- Your patches must be narrowly scoped to fix the specific vulnerability.
- You must preserve existing application behavior and routes.
- You must include a test plan and rollback plan for every proposal.

OUTPUT FORMAT:
Return a valid JSON object matching the RemediationProposal schema:
{
    "root_cause": "description of why the vulnerability exists",
    "proposed_remediation": "natural language description of the fix",
    "affected_files": ["list of files to modify"],
    "patches": [
        {
            "file_path": "relative/path/to/file.py",
            "operation": "modify",
            "patch_diff": "full corrected file content"
        }
    ],
    "expected_security_effect": "what security improvement this achieves",
    "expected_behavior": "how the application should behave after the fix",
    "test_plan": "how to verify the fix works",
    "rollback_plan": "how to undo if the fix breaks things",
    "risk_assessment": "risk of applying this fix"
}
"""


def build_remediation_user_prompt(
    finding: VulnerabilityFinding,
    target: ApplicationTarget,
    policy: RemediationPolicy,
    source_code: str = "",
) -> str:
    """User prompt containing vulnerability details and constraints."""
    return f"""<VULNERABILITY_FINDING>
finding_id: {finding.finding_id}
category: {finding.vulnerability_category}
component: {finding.affected_component}
severity: {finding.severity.value}
confidence: {finding.confidence.value}
technique: {finding.attack_technique_id}
evidence: {finding.evidence}
reproduction: {finding.reproduction_info}
root_cause: {finding.root_cause_hypothesis or 'Not yet analyzed'}
</VULNERABILITY_FINDING>

<TARGET_INFO>
name: {target.name}
environment: {target.environment.value}
type: {target.target_type.value}
</TARGET_INFO>

<POLICY_CONSTRAINTS>
max_files_changed: {policy.MAX_FILES_CHANGED}
max_patch_size_bytes: {policy.MAX_PATCH_SIZE_BYTES}
max_total_patch_bytes: {policy.MAX_TOTAL_PATCH_BYTES}
allowed_paths: {', '.join(policy.ALLOWED_PATHS)}
forbidden_paths: {', '.join(policy.FORBIDDEN_PATHS)}
cannot_modify_infrastructure: {policy.CANNOT_MODIFY_INFRASTRUCTURE}
cannot_modify_security_controls: {policy.CANNOT_MODIFY_SECURITY_CONTROLS}
cannot_remove_functionality: {policy.CANNOT_REMOVE_FUNCTIONALITY}
</POLICY_CONSTRAINTS>

{f'<SOURCE_CODE>{source_code}</SOURCE_CODE>' if source_code else ''}

Generate a structured remediation proposal as JSON. Follow the system prompt output format exactly.
"""


def sanitize_remediation_input(text: str) -> str:
    """Strip control characters and dangerous content from LLM output."""
    # Remove null bytes
    text = text.replace("\x00", "")
    # Remove other dangerous control characters (keep newlines/tabs)
    text = "".join(
        ch for ch in text
        if ch in ("\n", "\t", "\r") or (ord(ch) >= 32)
    )
    # Truncate to reasonable size
    if len(text) > 32768:
        text = text[:32768]
    return text
