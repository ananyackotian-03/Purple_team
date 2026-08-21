"""SentinelForge Branch 2 — Main Remediation Orchestrator.

Controls the remediation loop: find → propose → validate → clone → apply →
build/test → retest → verify/iterate.

All significant state transitions are persisted to the database for auditability.
"""

import json
import logging
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from sentinelforge.remediation.clone_manager import CloneManager
from sentinelforge.remediation.exceptions import (
    RemediationBudgetExhausted,
    RemediationPolicyViolation,
)
from sentinelforge.remediation.executor import CloneRemediationExecutor
from sentinelforge.remediation.models import (
    ApplicationTarget,
    RemediationBudget,
    RemediationExecutionResult,
    RemediationOutcome,
    RemediationProposal,
    TargetClone,
    VulnerabilityFinding,
    VulnerabilityRetestResult,
    VulnerabilityStatus,
)
from sentinelforge.remediation.persistence import (
    AuditEventPersistence,
    AuditEventType,
    AttemptPersistence,
    FindingPersistence,
    ProposalPersistence,
    RetestPersistence,
    VerificationPersistence,
    _sanitize_metadata,
)
from sentinelforge.remediation.policy import RemediationPolicy, RemediationPolicyValidator
from sentinelforge.remediation.retest import VulnerabilityRetestOrchestrator

logger = logging.getLogger(__name__)


class RemediationOrchestrator:
    """Main Branch 2 orchestrator. Controls the bounded remediation loop.

    The LLM cannot control the loop. Budget enforcement is deterministic Python.
    All state transitions are persisted for auditability.
    """

    def __init__(
        self,
        clone_manager: Optional[CloneManager] = None,
        executor: Optional[CloneRemediationExecutor] = None,
        retest_orchestrator: Optional[VulnerabilityRetestOrchestrator] = None,
        policy: Optional[RemediationPolicy] = None,
        budget: Optional[RemediationBudget] = None,
        persistence_factory=None,
    ):
        self._clone_manager = clone_manager or CloneManager()
        self._executor = executor or CloneRemediationExecutor(self._clone_manager)
        self._retest = retest_orchestrator or VulnerabilityRetestOrchestrator()
        self._policy = policy or RemediationPolicy()
        self._budget = budget or RemediationBudget()

        # Persistence (optional — backward compatible)
        self._findings = FindingPersistence(persistence_factory) if persistence_factory else None
        self._proposals = ProposalPersistence(persistence_factory) if persistence_factory else None
        self._attempts = AttemptPersistence(persistence_factory) if persistence_factory else None
        self._verifications = VerificationPersistence(persistence_factory) if persistence_factory else None
        self._retests = RetestPersistence(persistence_factory) if persistence_factory else None
        self._audit = AuditEventPersistence(persistence_factory) if persistence_factory else None
        self._session_factory = persistence_factory

    def remediate_vulnerability(
        self,
        finding: VulnerabilityFinding,
        target: ApplicationTarget,
        proposal: RemediationProposal,
        exercise_id: Optional[UUID] = None,
    ) -> RemediationOutcome:
        """Execute the remediation loop for a single vulnerability.

        This is the deterministic control loop. The LLM does not control it.
        """
        correlation_id = uuid4()
        started_at = datetime.now(timezone.utc)
        iteration = 0
        llm_calls = 1  # The proposal was one LLM call

        # Validate budget
        if not self._budget.has_remaining(iteration, llm_calls, started_at):
            raise RemediationBudgetExhausted("Budget exhausted before starting")

        # Persist finding if DB available
        if self._findings:
            self._findings.update_status(
                finding.finding_id, finding.organization_id, "REMEDIATING"
            )
            self._audit_event(
                finding.organization_id, exercise_id, correlation_id,
                "VulnerabilityFinding", finding.finding_id,
                AuditEventType.FINDING_CREATED,
            )

        # Create isolated clone
        clone = self._clone_manager.create_clone(target)

        if self._audit:
            self._audit_event(
                finding.organization_id, exercise_id, correlation_id,
                "TargetClone", clone.clone_id,
                AuditEventType.CLONE_CREATED,
                metadata={"source_target_id": str(target.target_id)},
            )

        try:
            while iteration < self._budget.max_iterations:
                iteration += 1
                finding.iteration_count = iteration

                # Validate proposal against policy
                is_valid, reason = RemediationPolicyValidator.validate(
                    proposal, self._policy
                )
                if not is_valid:
                    finding.status = VulnerabilityStatus.REMEDIATION_FAILED
                    if self._proposals:
                        self._proposals.update_status(
                            proposal.proposal_id, proposal.organization_id, "REJECTED"
                        )
                    if self._audit:
                        self._audit_event(
                            finding.organization_id, exercise_id, correlation_id,
                            "RemediationProposal", proposal.proposal_id,
                            AuditEventType.REMEDIATION_REJECTED,
                            metadata={"reason": reason},
                        )
                    return RemediationOutcome.REMEDIATION_FAILED

                # Persist proposal validation
                if self._proposals:
                    self._proposals.update_status(
                        proposal.proposal_id, proposal.organization_id, "VALIDATED"
                    )
                if self._audit:
                    self._audit_event(
                        finding.organization_id, exercise_id, correlation_id,
                        "RemediationProposal", proposal.proposal_id,
                        AuditEventType.REMEDIATION_VALIDATED,
                    )

                # Persist attempt
                attempt_record = None
                if self._attempts:
                    attempt_record = self._attempts.create(
                        organization_id=finding.organization_id,
                        finding_id=finding.finding_id,
                        proposal_id=proposal.proposal_id,
                        clone_id=clone.clone_id,
                        attempt_number=iteration,
                    )
                    # Transition: PROPOSED -> VALIDATED
                    self._attempts.update_status(
                        attempt_record.id, finding.organization_id, "VALIDATED",
                    )

                # Execute remediation
                try:
                    exec_result = self._executor.execute(
                        proposal=proposal,
                        clone=clone,
                        original_source_path=target.local_path,
                        policy=self._policy,
                    )
                except RemediationPolicyViolation:
                    if attempt_record and self._attempts:
                        self._attempts.update_status(
                            attempt_record.id, finding.organization_id, "FAILED",
                            failure_reason="Policy violation",
                        )
                    finding.status = VulnerabilityStatus.REMEDIATION_FAILED
                    if self._audit:
                        self._audit_event(
                            finding.organization_id, exercise_id, correlation_id,
                            "RemediationAttempt", attempt_record.id if attempt_record else uuid4(),
                            AuditEventType.BUILD_FAILED,
                            metadata={"reason": "Policy violation"},
                        )
                    return RemediationOutcome.REMEDIATION_FAILED

                # Persist execution results
                if attempt_record and self._attempts:
                    self._attempts.update_status(
                        attempt_record.id, finding.organization_id, "APPLIED",
                        changes_applied=exec_result.changes_applied,
                        build_passed=exec_result.build_passed,
                        tests_passed=exec_result.tests_passed,
                        behavior_preserved=exec_result.behavior_preserved,
                        build_output=exec_result.build_output[:2000] if exec_result.build_output else None,
                        test_output=exec_result.test_output[:2000] if exec_result.test_output else None,
                    )

                if self._audit:
                    event_type = AuditEventType.BUILD_PASSED if exec_result.build_passed else AuditEventType.BUILD_FAILED
                    self._audit_event(
                        finding.organization_id, exercise_id, correlation_id,
                        "RemediationAttempt", attempt_record.id if attempt_record else uuid4(),
                        event_type,
                        metadata={
                            "build_passed": exec_result.build_passed,
                            "tests_passed": exec_result.tests_passed,
                            "changes_applied": exec_result.changes_applied,
                        },
                    )

                # Check build and test
                if not exec_result.build_passed or not exec_result.tests_passed:
                    if attempt_record and self._attempts:
                        self._attempts.update_status(
                            attempt_record.id, finding.organization_id, "ROLLED_BACK",
                            rollback_status="ROLLBACK_DUE_TO_FAILURE",
                        )
                    self._clone_manager.rollback_clone(
                        clone, self._clone_manager.snapshot_clone(clone),
                        target.local_path,
                    )
                    if self._audit:
                        self._audit_event(
                            finding.organization_id, exercise_id, correlation_id,
                            "TargetClone", clone.clone_id,
                            AuditEventType.ROLLBACK_COMPLETED,
                        )
                    finding.status = VulnerabilityStatus.REMEDIATING
                    continue

                # Persist testing phase
                if attempt_record and self._attempts:
                    self._attempts.update_status(
                        attempt_record.id, finding.organization_id, "TESTING",
                    )

                # Red retest
                if self._audit:
                    self._audit_event(
                        finding.organization_id, exercise_id, correlation_id,
                        "RemediationAttempt", attempt_record.id if attempt_record else uuid4(),
                        AuditEventType.RETEST_STARTED,
                    )

                retest_result = self._retest.execute_retest(
                    finding=finding,
                    proposal=proposal,
                    clone=clone,
                    attempt_number=iteration,
                    max_variants=self._budget.max_variants_per_retest,
                )

                # Persist retest result
                if self._retests:
                    self._retests.create(
                        organization_id=finding.organization_id,
                        finding_id=finding.finding_id,
                        proposal_id=proposal.proposal_id,
                        clone_id=clone.clone_id,
                        attempt_number=iteration,
                        original_attack_blocked=retest_result.original_attack_blocked,
                        original_attack_evidence=retest_result.original_attack_evidence,
                        variants_tested=retest_result.variants_tested,
                        variants_blocked=retest_result.variants_blocked,
                        variant_details=json.dumps(retest_result.variant_details) if retest_result.variant_details else None,
                        regression_tests_passed=retest_result.regression_tests_passed,
                        application_functional=retest_result.application_functional,
                        vulnerability_eliminated=retest_result.vulnerability_eliminated,
                        retest_outcome=retest_result.retest_outcome,
                    )

                if self._audit:
                    self._audit_event(
                        finding.organization_id, exercise_id, correlation_id,
                        "RemediationAttempt", attempt_record.id if attempt_record else uuid4(),
                        AuditEventType.RETEST_COMPLETED,
                        metadata={
                            "vulnerability_eliminated": retest_result.vulnerability_eliminated,
                            "retest_outcome": retest_result.retest_outcome,
                            "original_attack_blocked": retest_result.original_attack_blocked,
                        },
                    )

                if retest_result.vulnerability_eliminated:
                    finding.status = VulnerabilityStatus.REMEDIATION_VERIFIED
                    if attempt_record and self._attempts:
                        self._attempts.update_status(
                            attempt_record.id, finding.organization_id, "VERIFIED",
                        )

                    # Persist verification
                    if self._verifications:
                        self._verifications.create(
                            organization_id=finding.organization_id,
                            finding_id=finding.finding_id,
                            remediation_attempt_id=attempt_record.id if attempt_record else uuid4(),
                            original_attack_blocked=retest_result.original_attack_blocked,
                            original_attack_evidence=retest_result.original_attack_evidence,
                            retest_outcome=retest_result.retest_outcome,
                            retest_evidence=f"Variants: {retest_result.variants_tested} tested, {retest_result.variants_blocked} blocked",
                            regression_tests_passed=retest_result.regression_tests_passed,
                            application_functional=retest_result.application_functional,
                            verification_decision="VERIFIED",
                            verification_reason=f"Original attack blocked={retest_result.original_attack_blocked}, "
                                               f"regression passed={retest_result.regression_tests_passed}, "
                                               f"app functional={retest_result.application_functional}",
                        )

                    if self._audit:
                        self._audit_event(
                            finding.organization_id, exercise_id, correlation_id,
                            "RemediationAttempt", attempt_record.id if attempt_record else uuid4(),
                            AuditEventType.VERIFICATION_PASSED,
                        )

                    return RemediationOutcome.VERIFIED

                # Not verified; check budget
                if not self._budget.has_remaining(iteration, llm_calls, started_at):
                    finding.status = VulnerabilityStatus.REQUIRES_HUMAN_REVIEW
                    if attempt_record and self._attempts:
                        self._attempts.update_status(
                            attempt_record.id, finding.organization_id, "REQUIRES_HUMAN_REVIEW",
                            failure_reason="Budget exhausted without verification",
                        )
                    if self._audit:
                        self._audit_event(
                            finding.organization_id, exercise_id, correlation_id,
                            "RemediationAttempt", attempt_record.id if attempt_record else uuid4(),
                            AuditEventType.VERIFICATION_FAILED,
                            metadata={"reason": "Budget exhausted"},
                        )
                    return RemediationOutcome.REQUIRES_HUMAN_REVIEW

                # Rollback for next attempt
                if attempt_record and self._attempts:
                    self._attempts.update_status(
                        attempt_record.id, finding.organization_id, "ROLLED_BACK",
                        rollback_status="ROLLBACK_FOR_NEXT_ATTEMPT",
                    )
                self._clone_manager.rollback_clone(
                    clone, self._clone_manager.snapshot_clone(clone),
                    target.local_path,
                )
                if self._audit:
                    self._audit_event(
                        finding.organization_id, exercise_id, correlation_id,
                        "TargetClone", clone.clone_id,
                        AuditEventType.ROLLBACK_COMPLETED,
                    )

            # Budget exhausted
            finding.status = VulnerabilityStatus.REQUIRES_HUMAN_REVIEW
            if self._audit:
                self._audit_event(
                    finding.organization_id, exercise_id, correlation_id,
                    "VulnerabilityFinding", finding.finding_id,
                    AuditEventType.VERIFICATION_FAILED,
                    metadata={"reason": "Max iterations reached"},
                )
            return RemediationOutcome.REQUIRES_HUMAN_REVIEW

        finally:
            # Always clean up clone
            self._clone_manager.cleanup_clone(clone)
            if self._audit:
                self._audit_event(
                    finding.organization_id, exercise_id, correlation_id,
                    "TargetClone", clone.clone_id,
                    AuditEventType.CLONE_DESTROYED,
                )

    def validate_proposal(
        self,
        proposal: RemediationProposal,
    ) -> tuple:
        """Validate a remediation proposal against policy. Returns (is_valid, reason)."""
        return RemediationPolicyValidator.validate(proposal, self._policy)

    def _audit_event(
        self,
        organization_id: UUID,
        exercise_id: Optional[UUID],
        correlation_id: UUID,
        entity_type: str,
        entity_id: UUID,
        event_type: str,
        metadata: Optional[dict] = None,
    ):
        """Record an audit event. Exceptions are logged but never propagated."""
        try:
            self._audit.record(
                organization_id=organization_id,
                exercise_id=exercise_id,
                entity_type=entity_type,
                entity_id=entity_id,
                event_type=event_type,
                correlation_id=correlation_id,
                metadata=metadata,
            )
        except Exception as exc:
            logger.warning("Failed to record audit event %s: %s", event_type, exc)
