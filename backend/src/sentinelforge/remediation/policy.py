"""SentinelForge Branch 2 — Deterministic Remediation Policy Validator.

The LLM MUST NOT bypass these rules. All validation is deterministic Python.
"""

import re
from typing import List, Optional, Tuple

from sentinelforge.remediation.exceptions import RemediationPolicyViolation
from sentinelforge.remediation.models import RemediationProposal


class RemediationPolicy:
    """Default policy constraints for remediation proposals.

    These limits are enforced deterministically. The LLM cannot modify them.
    """

    # File constraints
    ALLOWED_PATHS: List[str] = [
        "app/", "src/", "lib/", "routes/", "controllers/",
        "models/", "services/", "vulnerable_app/", "tests/",
    ]
    FORBIDDEN_PATHS: List[str] = [
        "Dockerfile", "docker-compose.yml", ".github/", ".gitlab-ci.yml",
        "Makefile", "pyproject.toml", "package.json", "requirements.txt",
        "sentinelforge/", "backend/",
    ]
    FORBIDDEN_FILE_PATTERNS: List[str] = [
        r".*\.env$", r".*secret.*", r".*credential.*",
        r".*\.pem$", r".*\.key$", r".*\.p12$", r".*\.pfx$",
    ]
    MAX_FILES_CHANGED: int = 5
    MAX_PATCH_SIZE_BYTES: int = 16384   # 16KB per file
    MAX_TOTAL_PATCH_BYTES: int = 65536  # 64KB total
    MAX_REMEDIATION_ATTEMPTS: int = 3

    # Content constraints
    FORBIDDEN_OPERATIONS: List[str] = [
        "disable_auth", "remove_validation", "disable_cors",
        "disable_rate_limit", "drop_table", "truncate",
        "disable authentication", "bypass security", "remove csrf",
        "turn off cors", "skip validation", "disable logging",
    ]
    REQUIRE_TEST_PASS: bool = True
    REQUIRE_BEHAVIOR_PRESERVATION: bool = True

    # Security constraints
    CANNOT_MODIFY_INFRASTRUCTURE: bool = True
    CANNOT_MODIFY_SECURITY_CONTROLS: bool = True
    CANNOT_REMOVE_FUNCTIONALITY: bool = True
    CANNOT_ACCESS_SECRETS: bool = True


class RemediationPolicyValidator:
    """Validates a RemediationProposal against RemediationPolicy constraints.

    Returns (is_valid, reason) tuples. Raises RemediationPolicyViolation
    when callers prefer exceptions.
    """

    @staticmethod
    def validate(
        proposal: RemediationProposal,
        policy: Optional[RemediationPolicy] = None,
    ) -> Tuple[bool, str]:
        """Validate proposal against policy. Returns (is_valid, reason)."""
        policy = policy or RemediationPolicy()

        # 1. No patches
        if not proposal.patches:
            return False, "No patches provided in remediation proposal"

        # 2. Number of affected files
        if len(proposal.affected_files) > policy.MAX_FILES_CHANGED:
            return False, (
                f"Too many files changed: {len(proposal.affected_files)} > "
                f"{policy.MAX_FILES_CHANGED}"
            )

        # 2. Each patch size
        for patch in proposal.patches:
            patch_bytes = len(patch.patch_diff.encode("utf-8"))
            if patch_bytes > policy.MAX_PATCH_SIZE_BYTES:
                return False, (
                    f"Patch too large for {patch.file_path}: {patch_bytes} bytes > "
                    f"{policy.MAX_PATCH_SIZE_BYTES}"
                )

        # 3. Total patch size
        total_bytes = sum(
            len(p.patch_diff.encode("utf-8")) for p in proposal.patches
        )
        if total_bytes > policy.MAX_TOTAL_PATCH_BYTES:
            return False, (
                f"Total patch size too large: {total_bytes} bytes > "
                f"{policy.MAX_TOTAL_PATCH_BYTES}"
            )

        # 4. Path traversal check
        for fpath in proposal.affected_files:
            normalized = fpath.replace("\\", "/")
            if ".." in normalized:
                return False, f"Path traversal detected in: {fpath}"
            if normalized.startswith("/"):
                return False, f"Absolute path not allowed: {fpath}"
            # Check for Windows absolute paths
            if re.match(r"^[A-Za-z]:\\", normalized):
                return False, f"Absolute path not allowed: {fpath}"

        # 5. Forbidden file patterns
        for fpath in proposal.affected_files:
            for pattern in policy.FORBIDDEN_FILE_PATTERNS:
                if re.match(pattern, fpath, re.IGNORECASE):
                    return False, f"Forbidden file pattern '{pattern}' matched: {fpath}"

        # 6. Forbidden paths
        for fpath in proposal.affected_files:
            normalized = fpath.replace("\\", "/").lstrip("/")
            for forbidden in policy.FORBIDDEN_PATHS:
                forbidden_clean = forbidden.rstrip("/")
                if normalized == forbidden_clean or normalized.startswith(forbidden_clean + "/") or normalized.startswith(forbidden_clean):
                    return False, f"Forbidden path '{forbidden}' matched: {fpath}"

        # 7. Forbidden operations in remediation text
        remediation_lower = proposal.proposed_remediation.lower()
        for op in policy.FORBIDDEN_OPERATIONS:
            if op.lower() in remediation_lower:
                return False, f"Forbidden operation detected: {op}"

        # 8. Sentinelforge path protection
        for fpath in proposal.affected_files:
            if "sentinelforge" in fpath.lower():
                return False, f"Cannot modify sentinelforge paths: {fpath}"

        # 9. Forbidden content in patch diffs
        forbidden_content = [
            "disable authentication", "bypass security", "remove csrf",
            "turn off cors", "skip validation", "disable logging",
            "disable_auth", "remove_validation",
        ]
        for patch in proposal.patches:
            diff_lower = patch.patch_diff.lower()
            for content in forbidden_content:
                if content.lower() in diff_lower:
                    return False, f"Forbidden content in patch for {patch.file_path}: {content}"

        return True, "Remediation proposal passes all policy constraints"

    @staticmethod
    def validate_or_raise(
        proposal: RemediationProposal,
        policy: Optional[RemediationPolicy] = None,
    ) -> None:
        """Validate proposal. Raises RemediationPolicyViolation if invalid."""
        is_valid, reason = RemediationPolicyValidator.validate(proposal, policy)
        if not is_valid:
            raise RemediationPolicyViolation(reason)
