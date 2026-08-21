"""SentinelForge Branch 2 — Application Vulnerability Remediation Package.

Provides the remediation pipeline for application vulnerabilities discovered
by the Red Agent: vulnerability classification, remediation proposal validation,
isolated clone management, fix application, build/test, and adversarial retest.

SECURITY INVARIANTS:
- Production applications are NEVER modified by SentinelForge.
- All remediation operations execute exclusively against isolated clones.
- The LLM is an untrusted proposal generator; deterministic infrastructure
  validates and applies remediations.
"""

from sentinelforge.remediation.models import (
    ApplicationTarget,
    CloneSnapshot,
    CloneStatus,
    PatchSpec,
    RemediationBudget,
    RemediationExecutionResult,
    RemediationOutcome,
    RemediationProposal,
    TargetClone,
    TargetEnvironment,
    TargetType,
    VulnerabilityConfidence,
    VulnerabilityFinding,
    VulnerabilityRetestResult,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from sentinelforge.remediation.policy import RemediationPolicy, RemediationPolicyValidator
from sentinelforge.remediation.executor import CloneRemediationExecutor
from sentinelforge.remediation.retest import VulnerabilityRetestOrchestrator
from sentinelforge.remediation.orchestrator import RemediationOrchestrator
from sentinelforge.remediation.exceptions import (
    CloneCreationFailed,
    RemediationBudgetExhausted,
    RemediationException,
    RemediationPolicyViolation,
    RollbackFailed,
    VulnerabilityClassificationError,
)

__all__ = [
    "ApplicationTarget",
    "CloneSnapshot",
    "CloneStatus",
    "CloneCreationFailed",
    "CloneRemediationExecutor",
    "PatchSpec",
    "RemediationBudget",
    "RemediationException",
    "RemediationExecutionResult",
    "RemediationOrchestrator",
    "RemediationOutcome",
    "RemediationPolicy",
    "RemediationPolicyViolation",
    "RemediationPolicyValidator",
    "RemediationProposal",
    "RollbackFailed",
    "TargetClone",
    "TargetEnvironment",
    "TargetType",
    "VulnerabilityClassificationError",
    "VulnerabilityConfidence",
    "VulnerabilityFinding",
    "VulnerabilityRetestOrchestrator",
    "VulnerabilityRetestResult",
    "VulnerabilitySeverity",
    "VulnerabilityStatus",
]
