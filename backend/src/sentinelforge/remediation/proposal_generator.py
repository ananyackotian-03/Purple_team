"""SentinelForge — LLM-powered Remediation Proposal Generator.

Uses the existing LLMProvider abstraction to generate structured
RemediationProposal objects from VulnerabilityFinding context.

SECURITY ROLE:
- The LLM is an UNTRUSTED proposal generator.
- Proposals are validated by RemediationPolicyValidator before execution.
- The LLM never directly edits files or touches the clone.
"""

import os
from typing import Optional

from sentinelforge.agents.red.provider import LLMProvider, ProviderAPIError
from sentinelforge.agents.red.schemas import _MAX_TEXT_LEN
from sentinelforge.remediation.exceptions import RemediationPolicyViolation
from sentinelforge.remediation.models import (
    ApplicationTarget,
    RemediationProposal,
    VulnerabilityFinding,
)
from sentinelforge.remediation.policy import RemediationPolicy, RemediationPolicyValidator
from sentinelforge.remediation.prompts import (
    build_remediation_system_prompt,
    build_remediation_user_prompt,
)


class ProposalGenerationError(Exception):
    """Raised when proposal generation fails."""


class RemediationProposalGenerator:
    """Generates RemediationProposal objects using an LLMProvider.

    The LLM proposes; deterministic infrastructure validates.
    """

    def __init__(
        self,
        provider: LLMProvider,
        policy: Optional[RemediationPolicy] = None,
        max_retries: int = 2,
    ):
        self._provider = provider
        self._policy = policy or RemediationPolicy()
        self._max_retries = max_retries

    def generate(
        self,
        finding: VulnerabilityFinding,
        target: ApplicationTarget,
        source_code: str = "",
    ) -> RemediationProposal:
        """Generate a remediation proposal for a confirmed vulnerability.

        Args:
            finding: The confirmed vulnerability finding.
            target: The application target.
            source_code: Bounded source code context (optional).

        Returns:
            Validated RemediationProposal.

        Raises:
            ProposalGenerationError: If generation or validation fails.
        """
        system_prompt = build_remediation_system_prompt()
        user_prompt = build_remediation_user_prompt(
            finding=finding,
            target=target,
            policy=self._policy,
            source_code=source_code[:8192],  # Bound context size
        )

        last_error = None
        for attempt in range(self._max_retries + 1):
            try:
                raw_response = self._provider.generate(
                    prompt=user_prompt,
                    system_prompt=system_prompt,
                    temperature=0.2,
                )

                proposal = self._parse_proposal(raw_response, finding, target)

                is_valid, reason = RemediationPolicyValidator.validate(
                    proposal, self._policy
                )
                if not is_valid:
                    last_error = ProposalGenerationError(
                        f"Policy validation failed (attempt {attempt + 1}): {reason}"
                    )
                    continue

                return proposal

            except ProviderAPIError as exc:
                raise ProposalGenerationError(
                    f"LLM provider error: {exc}"
                ) from exc
            except ProposalGenerationError:
                raise
            except Exception as exc:
                last_error = ProposalGenerationError(
                    f"Proposal generation failed (attempt {attempt + 1}): {exc}"
                )
                continue

        raise last_error or ProposalGenerationError("All generation attempts failed")

    def _parse_proposal(
        self,
        raw_response: str,
        finding: VulnerabilityFinding,
        target: ApplicationTarget,
    ) -> RemediationProposal:
        """Parse raw LLM response into a RemediationProposal.

        Attempts JSON parsing first, falls back to constructing from text.
        """
        import json

        try:
            data = json.loads(raw_response)
            return RemediationProposal(
                finding_id=finding.finding_id,
                organization_id=finding.organization_id,
                root_cause=data.get("root_cause", finding.root_cause_hypothesis or "Unknown"),
                proposed_remediation=data.get("proposed_remediation", ""),
                affected_files=data.get("affected_files", []),
                patches=data.get("patches", []),
                expected_security_effect=data.get("expected_security_effect", ""),
                expected_behavior=data.get("expected_behavior", ""),
                test_plan=data.get("test_plan", ""),
                rollback_plan=data.get("rollback_plan", ""),
                risk_assessment=data.get("risk_assessment", ""),
            )
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

        # Fallback: construct a minimal proposal from the finding
        return RemediationProposal(
            finding_id=finding.finding_id,
            organization_id=finding.organization_id,
            root_cause=finding.root_cause_hypothesis or f"SQL injection in {finding.affected_component}",
            proposed_remediation=raw_response[:2048],
            affected_files=[],
            patches=[],
            expected_security_effect="Prevent exploitation of the identified vulnerability",
            expected_behavior="Application continues to function normally",
            test_plan="Re-run original attack; verify it no longer succeeds",
            rollback_plan="Revert clone to snapshot",
            risk_assessment="Low - isolated clone only",
        )
