# SentinelForge — Application Vulnerability Remediation (Branch 2) Implementation Plan

**Document Version**: 1.0.0
**Status**: PROPOSED / AWAITING APPROVAL
**Target Milestone**: Branch 2 Vertical Slice — SQL Injection Remediation Loop
**Depends On**: Branch 1 (fully implemented)

---

## Executive Summary

This document details the step-by-step implementation plan for Branch 2 of SentinelForge: Application Vulnerability Remediation. Branch 2 enables the Red Agent to discover application vulnerabilities, propose remediations, test fixes in isolated clones, and verify whether vulnerabilities have been eliminated through adversarial retesting.

**Branch 1 (Detection Gap Remediation) is fully implemented and must NOT be modified or broken.**

The vertical slice proves one complete loop: vulnerable Flask app → Red Agent discovers SQL injection → LLM proposes parameterized query fix → clone created → fix applied → build/test → Red Agent reattacks → VERIFIED.

---

## Current Status

### Branch 1: COMPLETED
- 263 tests passing (229 unit + 34 Docker integration)
- Full detection gap → Blue Agent → Sigma rule → Retest → VERIFIED loop
- All security primitives validated

### Branch 2: NOT IMPLEMENTED
- Zero existing code for Branch 2
- No vulnerability model, no clone abstraction, no remediation engine
- Only scaffolding: `REMEDIATING` state and `remediation_status` column

---

## Proposed Directory & Package Structure

New package: `backend/src/sentinelforge/remediation/`

```
backend/src/sentinelforge/remediation/
├── __init__.py                          # Public exports
├── models.py                            # Domain models (VulnerabilityFinding, TargetClone, etc.)
├── policy.py                            # RemediationPolicy deterministic validator
├── executor.py                          # CloneRemediationExecutor
├── retest.py                            # VulnerabilityRetestOrchestrator
├── orchestrator.py                      # RemediationOrchestrator (main loop)
├── budget.py                            # RemediationBudget enforcement
├── clone_manager.py                     # Clone lifecycle management
├── exceptions.py                        # Branch 2 exception hierarchy
└── prompts.py                           # LLM prompt templates for remediation proposals
```

---

## Detailed File Modifications & Implementations

### Phase 1: Domain Models & Exceptions (Foundation)

#### 1.1 `backend/src/sentinelforge/remediation/__init__.py` [NEW]

Public exports for the remediation package.

```python
from sentinelforge.remediation.models import (
    VulnerabilityFinding, VulnerabilitySeverity, VulnerabilityConfidence, VulnerabilityStatus,
    ApplicationTarget, TargetType, TargetEnvironment,
    TargetClone, CloneStatus,
    RemediationProposal, PatchSpec,
    RemediationExecutionResult, RemediationBudget,
    CloneSnapshot,
    VulnerabilityRetestResult,
)
from sentinelforge.remediation.policy import RemediationPolicy, RemediationPolicyValidator
from sentinelforge.remediation.executor import CloneRemediationExecutor
from sentinelforge.remediation.retest import VulnerabilityRetestOrchestrator
from sentinelforge.remediation.orchestrator import RemediationOrchestrator
from sentinelforge.remediation.exceptions import (
    RemediationException, RemediationBudgetExhausted, RemediationPolicyViolation,
    CloneCreationFailed, RollbackFailed, VulnerabilityClassificationError,
)
```

#### 1.2 `backend/src/sentinelforge/remediation/exceptions.py` [NEW]

Branch 2 exception hierarchy. Follows the pattern of `agents/red/exceptions.py`.

```python
class RemediationException(Exception):
    """Base exception for all Branch 2 remediation operations."""
    pass

class RemediationBudgetExhausted(RemediationException):
    """Raised when remediation budget limits are reached."""
    pass

class RemediationPolicyViolation(RemediationException):
    """Raised when a remediation proposal violates RemediationPolicy."""
    pass

class CloneCreationFailed(RemediationException):
    """Raised when an isolated clone cannot be created."""
    pass

class RollbackFailed(RemediationException):
    """Raised when a clone cannot be restored to a previous snapshot."""
    pass

class VulnerabilityClassificationError(RemediationException):
    """Raised when an observation cannot be classified as a vulnerability."""
    pass
```

#### 1.3 `backend/src/sentinelforge/remediation/models.py` [NEW]

All Branch 2 domain models. Follows the Pydantic v2 pattern of `domain/experiment.py`.

Contains:
- `VulnerabilitySeverity`, `VulnerabilityConfidence`, `VulnerabilityStatus` (str Enums)
- `VulnerabilityFinding` (BaseModel)
- `TargetType`, `TargetEnvironment` (str Enums)
- `ApplicationTarget` (BaseModel)
- `CloneStatus` (str Enum)
- `TargetClone` (BaseModel)
- `RemediationProposal`, `PatchSpec` (BaseModel)
- `RemediationExecutionResult` (BaseModel)
- `RemediationBudget` (BaseModel)
- `CloneSnapshot` (BaseModel)
- `VulnerabilityRetestResult` (BaseModel)

**Security constraints on models:**
- All models carry `organization_id` for tenant isolation
- `RemediationProposal` patches carry `original_content_hash` and `new_content_hash`
- `TargetClone` has `original_secrets_excluded = True` as a field default
- `VulnerabilityFinding` has `max_iterations = 3` as a field default

#### 1.4 `backend/src/sentinelforge/remediation/policy.py` [NEW]

Deterministic `RemediationPolicy` and `RemediationPolicyValidator`.

```python
class RemediationPolicy:
    """Default policy constraints for remediation proposals."""

    # File constraints
    ALLOWED_PATHS = ["app/", "src/", "lib/", "routes/", "controllers/", "models/", "services/"]
    FORBIDDEN_PATHS = ["Dockerfile", "docker-compose.yml", ".github/", ".gitlab-ci.yml", "Makefile", "pyproject.toml", "package.json"]
    FORBIDDEN_FILE_PATTERNS = [r".*\.env$", r".*secret.*", r".*credential.*", r".*\.pem$", r".*\.key$"]
    MAX_FILES_CHANGED = 5
    MAX_PATCH_SIZE_BYTES = 16384
    MAX_TOTAL_PATCH_BYTES = 65536
    MAX_REMEDIATION_ATTEMPTS = 3

    # Content constraints
    FORBIDDEN_OPERATIONS = ["disable_auth", "remove_validation", "disable_cors", "disable_rate_limit"]
    REQUIRE_TEST_PASS = True
    REQUIRE_BEHAVIOR_PRESERVATION = True

    # Security constraints
    CANNOT_MODIFY_INFRASTRUCTURE = True
    CANNOT_MODIFY_SECURITY_CONTROLS = True
    CANNOT_REMOVE_FUNCTIONALITY = True
    CANNOT_ACCESS_SECRETS = True


class RemediationPolicyValidator:
    """Validates a RemediationProposal against RemediationPolicy constraints."""

    @staticmethod
    def validate(proposal: RemediationProposal, policy: RemediationPolicy = None) -> Tuple[bool, str]:
        """
        Returns (is_valid, reason).
        Checks:
        1. Number of affected files <= MAX_FILES_CHANGED
        2. Each patch <= MAX_PATCH_SIZE_BYTES
        3. Total patch size <= MAX_TOTAL_PATCH_BYTES
        4. All file paths in ALLOWED_PATHS
        5. No file path matches FORBIDDEN_FILE_PATTERNS
        6. No file in FORBIDDEN_PATHS
        7. No FORBIDDEN_OPERATIONS in proposed_remediation text
        8. affected_files does not contain sentinelforge paths
        """
        ...
```

#### 1.5 `backend/src/sentinelforge/remediation/budget.py` [NEW]

```python
class RemediationBudget:
    """Deterministic budget enforcement for remediation loops."""

    MAX_ITERATIONS = 3
    MAX_LLM_CALLS = 10
    MAX_WALL_TIME_SECONDS = 600
    MAX_VARIANTS_PER_RETEST = 3
    MAX_CLONE_LIFETIME_MINUTES = 30

    def assert_has_remaining(self, iteration: int, llm_calls: int, started_at: datetime) -> None:
        """Raise RemediationBudgetExhausted if any limit is reached."""
        ...
```

### Phase 2: Database Models & Migration

#### 2.1 `backend/src/sentinelforge/db/models.py` [MODIFY]

Add Branch 2 ORM tables. Appended AFTER existing tables. No modifications to existing tables.

New models:
- `ApplicationTargetRecord` (table: `application_targets`)
- `TargetCloneRecord` (table: `target_clones`)
- `VulnerabilityFindingRecord` (table: `vulnerability_findings`)
- `RemediationProposalRecord` (table: `remediation_proposals`)
- `RemediationAttemptRecord` (table: `remediation_attempts`)
- `RemediationRetestResultRecord` (table: `remediation_retest_results`)
- `CloneSnapshotRecord` (table: `clone_snapshots`)

All tables include:
- `id` (UUID primary key)
- `organization_id` (UUID FK → `organizations.id`, NOT NULL)
- `created_at` (DateTime, default CURRENT_TIMESTAMP)

#### 2.2 `backend/alembic/versions/002_application_remediation_schema.py` [NEW]

Alembic migration creating Branch 2 tables.

```python
"""Application Remediation Schema: Branch 2 tables

Revision ID: 002_app_remediation
Revises: 001_reconciliation
Create Date: 2026-08-19
"""
```

Tables created in order (respecting FK constraints):
1. `application_targets`
2. `target_clones`
3. `clone_snapshots`
4. `vulnerability_findings`
5. `remediation_proposals`
6. `remediation_attempts`
7. `remediation_retest_results`

### Phase 3: Clone Management

#### 3.1 `backend/src/sentinelforge/remediation/clone_manager.py` [NEW]

Manages the lifecycle of isolated clones. Uses `SafeDockerClient` for Docker operations.

```python
class CloneManager:
    """Creates, manages, and cleans up isolated target clones."""

    def create_clone(
        self,
        target: ApplicationTarget,
        organization_id: UUID,
        policy: RemediationPolicy = None,
    ) -> TargetClone:
        """
        1. Validate target authorization (not PRODUCTION)
        2. Pull/build source image or clone repository
        3. Create isolated Docker network
        4. Start container with resource limits
        5. Inject synthetic secrets (NEVER production secrets)
        6. Verify clone health
        7. Return TargetClone record
        """
        ...

    def snapshot_clone(self, clone: TargetClone) -> CloneSnapshot:
        """
        1. Record current version
        2. Hash all modified files in clone
        3. Create Docker commit snapshot
        4. Return CloneSnapshot record
        """
        ...

    def rollback_clone(self, clone: TargetClone, snapshot: CloneSnapshot) -> bool:
        """
        1. Restore Docker container to snapshot
        2. Verify file hashes match snapshot
        3. Return success/failure
        """
        ...

    def cleanup_clone(self, clone: TargetClone) -> None:
        """
        1. Stop container
        2. Remove Docker network
        3. Remove container
        4. Update CloneStatus to CLEANED_UP
        """
        ...

    def health_check(self, clone: TargetClone) -> bool:
        """Check if clone container is running and responsive."""
        ...
```

### Phase 4: Remediation Execution

#### 4.1 `backend/src/sentinelforge/remediation/executor.py` [NEW]

```python
class CloneRemediationExecutor:
    """Applies remediation proposals to isolated clones. NEVER touches production."""

    def __init__(self, clone_manager: CloneManager, adapter: SimulationAdapter):
        self._clone_manager = clone_manager
        self._adapter = adapter

    def execute(
        self,
        proposal: RemediationProposal,
        clone: TargetClone,
        policy: RemediationPolicy = None,
    ) -> RemediationExecutionResult:
        """
        1. Validate proposal against RemediationPolicy
        2. Snapshot clone (for rollback)
        3. Apply patches to clone filesystem
        4. Record each file change in audit log
        5. Build application in clone
        6. Run application test suite
        7. Validate application still functions
        8. Return RemediationExecutionResult
        """
        ...

    def _apply_patches(self, clone: TargetClone, patches: List[PatchSpec]) -> List[dict]:
        """Apply patches to clone, recording each change."""
        ...

    def _build_application(self, clone: TargetClone) -> BuildResult:
        """Build application inside clone container."""
        ...

    def _run_tests(self, clone: TargetClone) -> TestResult:
        """Run application test suite inside clone container."""
        ...

    def _validate_behavior(self, clone: TargetClone) -> BehaviorResult:
        """Validate application still functions (health check, core endpoints)."""
        ...
```

### Phase 5: Red Retest

#### 5.1 `backend/src/sentinelforge/remediation/retest.py` [NEW]

```python
class VulnerabilityRetestOrchestrator:
    """Orchestrates Red Agent retesting of remediated vulnerabilities."""

    def prepare_retest(
        self,
        finding: VulnerabilityFinding,
        proposal: RemediationProposal,
        clone: TargetClone,
    ) -> RetestRequest:
        """
        Creates a RetestRequest for the existing Red Agent infrastructure.
        The original attack scenario is reconstructed from finding.reproduction_info.
        """
        ...

    def execute_retest(
        self,
        retest_request: RetestRequest,
        finding: VulnerabilityFinding,
        clone_adapter: SimulationAdapter,
        sigma_engine: SigmaEngine,
        gap_evaluator: DetectionGapEvaluator,
        before_outcome: ScenarioDetectionOutcome,
        max_variants: int = 3,
    ) -> VulnerabilityRetestResult:
        """
        Stage 1: Replay original attack against remediated clone
        Stage 2: Test relevant attack variants (limited by max_variants)
        Stage 3: Regression testing (application health check)
        """
        ...

    def _test_variants(
        self,
        finding: VulnerabilityFinding,
        clone_adapter: SimulationAdapter,
        sigma_engine: SigmaEngine,
        gap_evaluator: DetectionGapEvaluator,
        max_variants: int,
    ) -> Tuple[int, int, List[dict]]:
        """Test attack variants. Returns (tested, blocked, details)."""
        ...
```

### Phase 6: Main Orchestrator

#### 6.1 `backend/src/sentinelforge/remediation/orchestrator.py` [NEW]

```python
class RemediationOrchestrator:
    """Main Branch 2 orchestrator. Controls the remediation loop."""

    def __init__(
        self,
        red_agent: RedAgent,
        clone_manager: CloneManager,
        executor: CloneRemediationExecutor,
        retest_orchestrator: VulnerabilityRetestOrchestrator,
        policy: RemediationPolicy = None,
        budget: RemediationBudget = None,
    ):
        ...

    def remediate_vulnerability(
        self,
        finding: VulnerabilityFinding,
        target: ApplicationTarget,
        organization_id: UUID,
    ) -> RemediationOutcome:
        """
        Main remediation loop:
        1. Validate target authorization
        2. Create isolated clone
        3. Loop (bounded by RemediationBudget):
           a. LLM generates RemediationProposal
           b. Validate proposal against RemediationPolicy
           c. Apply fix to clone
           d. Build & test
           e. Red Agent retest
           f. If VERIFIED → return success
           g. If FAILED → rollback, increment iteration, continue
           h. If budget exhausted → return REQUIRES_HUMAN_REVIEW
        4. Cleanup clone
        """
        ...

    def _propose_remediation(
        self,
        finding: VulnerabilityFinding,
        clone: TargetClone,
    ) -> RemediationProposal:
        """
        LLM generates a structured RemediationProposal.
        Follows the same pattern as RedAgent._obtain_decision():
        - Build context
        - Call LLMProvider.generate_structured()
        - Validate schema
        - Return proposal
        """
        ...

    def _validate_and_apply(
        self,
        proposal: RemediationProposal,
        clone: TargetClone,
    ) -> RemediationExecutionResult:
        """Validate proposal and apply to clone."""
        ...
```

### Phase 7: LLM Prompts

#### 7.1 `backend/src/sentinelforge/remediation/prompts.py` [NEW]

Prompt templates for LLM-generated remediation proposals. Follows the XML-fencing pattern of `agents/red/prompts.py`.

```python
def build_remediation_system_prompt() -> str:
    """System prompt for remediation proposal generation."""
    ...

def build_remediation_user_prompt(
    finding: VulnerabilityFinding,
    target: ApplicationTarget,
    clone: TargetClone,
    policy: RemediationPolicy,
) -> str:
    """User prompt containing vulnerability details and constraints."""
    ...

def sanitize_remediation_input(text: str) -> str:
    """Strip control characters and dangerous content from LLM output."""
    ...
```

### Phase 8: State Machine Extension

#### 8.1 `backend/src/sentinelforge/domain/state_machine.py` [MODIFY]

Add Branch 2 states to `VALID_TRANSITIONS`. The existing Branch 1 transitions are preserved EXACTLY as they are.

```python
VALID_TRANSITIONS = {
    # ... all existing Branch 1 transitions UNCHANGED ...

    # Branch 2: Application Vulnerability Remediation
    "VULNERABILITY_FOUND":    ["VULNERABILITY_ANALYZING", "COMPLETED"],
    "VULNERABILITY_ANALYZING": ["REMEDIATION_PROPOSED", "REQUIRES_HUMAN_REVIEW"],
    "REMEDIATION_PROPOSED":   ["REMEDIATION_VALIDATING", "REJECTED"],
    "REMEDIATION_VALIDATING": ["CLONE_CREATING", "REJECTED"],
    "CLONE_CREATING":         ["REMEDIATING"],
    "REMEDIATING":            ["RETESTING", "ROLLING_BACK"],
    "ROLLING_BACK":           ["REMEDIATING", "REMEDIATION_FAILED"],
    "RETESTING":              ["VERIFIED", "REMEDIATING", "REMEDIATION_FAILED"],
    "REMEDIATION_FAILED":     ["REQUIRES_HUMAN_REVIEW", "COMPLETED"],
    "REQUIRES_HUMAN_REVIEW":  ["COMPLETED"],
}
```

The `ExerciseStateMachine.transition()` method is extended with Branch 2 guard logic:

```python
@staticmethod
def transition(current_state, new_state, has_retest_result=False, retest_result=None):
    # ... existing Branch 1 logic UNCHANGED ...

    # Branch 2 VERIFIED guard (different from Branch 1)
    if new_state == "VERIFIED" and current_state == "RETESTING":
        res = retest_result if retest_result is not None else (...)
        if isinstance(res, VulnerabilityRetestResult):
            # Branch 2 verification: vulnerability_eliminated must be True
            if not getattr(res, "vulnerability_eliminated", False):
                raise SecurityRejection(VERIFICATION_FAILED, "vulnerability_eliminated must be True")
            # ... additional Branch 2 guards ...
        # Branch 1 verification (existing logic) remains for non-VulnerabilityRetestResult
        ...

    return new_state
```

### Phase 9: Exceptions & Security Codes

#### 9.1 `backend/src/sentinelforge/domain/exceptions.py` [MODIFY]

Add Branch 2 rejection codes:

```python
class SecurityRejectionCode(str, Enum):
    # ... existing codes UNCHANGED ...
    POLICY_DENIED = "POLICY_DENIED"
    INVALID_ACTION_IR = "INVALID_ACTION_IR"
    INVALID_TARGET = "INVALID_TARGET"
    INVALID_EXECUTABLE = "INVALID_EXECUTABLE"
    INVALID_ARGUMENTS = "INVALID_ARGUMENTS"
    UNAUTHORIZED_USER = "UNAUTHORIZED_USER"
    EXPIRED_BLUEPRINT = "EXPIRED_BLUEPRINT"
    INVALID_SIGNATURE = "INVALID_SIGNATURE"
    TAMPERED_BLUEPRINT = "TAMPERED_BLUEPRINT"
    REPLAY_DETECTED = "REPLAY_DETECTED"
    INVALID_STATE_TRANSITION = "INVALID_STATE_TRANSITION"
    VERIFICATION_FAILED = "VERIFICATION_FAILED"

    # Branch 2 NEW codes
    PRODUCTION_TARGET_NO_REMEDIATION = "PRODUCTION_TARGET_NO_REMEDIATION"
    REMEDIATION_POLICY_VIOLATION = "REMEDIATION_POLICY_VIOLATION"
    CLONE_CREATION_FAILED = "CLONE_CREATION_FAILED"
    ROLLBACK_FAILED = "ROLLBACK_FAILED"
    REMEDIATION_BUDGET_EXHAUSTED = "REMEDIATION_BUDGET_EXHAUSTED"
```

### Phase 10: Context Builder Extension

#### 10.1 `backend/src/sentinelforge/agents/red/context.py` [MODIFY]

Add vulnerability finding context for Red Agent retest. This is a minimal, additive change:

```python
class RedAgentContext:
    # ... existing fields UNCHANGED ...
    vulnerability_findings: List[Dict[str, Any]] = field(default_factory=list)  # NEW

class ContextBuilder:
    def build(self, objective, budget=None):
        # ... existing logic UNCHANGED ...
        findings = self._load_vulnerability_findings(org_id)  # NEW
        return RedAgentContext(
            # ... existing fields ...
            vulnerability_findings=findings,  # NEW
        )

    def _load_vulnerability_findings(self, org_id: UUID) -> List[Dict[str, Any]]:
        """Load open vulnerability findings for context."""
        ...
```

---

## Test Files

### New Test Files

| File | Tests | Type |
| :--- | :--- | :--- |
| `backend/tests/test_remediation_models.py` | 12 | Unit: model validation, schema, serialization |
| `backend/tests/test_remediation_policy.py` | 15 | Unit: policy validation, forbidden paths, limits |
| `backend/tests/test_remediation_budget.py` | 8 | Unit: budget enforcement, limits |
| `backend/tests/test_remediation_state_transitions.py` | 14 | Unit: Branch 2 state machine transitions |
| `backend/tests/test_remediation_orchestrator.py` | 10 | Unit: orchestrator loop logic (mocked) |
| `backend/tests/test_remediation_executor.py` | 10 | Unit: patch application, build, test (mocked) |
| `backend/tests/test_remediation_security.py` | 12 | Security: production write, path traversal, injection, cross-tenant |
| `backend/tests/integration/test_branch2_e2e.py` | 1 | E2E: full remediation loop with vulnerable Flask app |

**Estimated total: ~82 new tests**

### Existing Test Files

No existing test files are modified. Branch 1 tests continue to pass unchanged.

---

## E2E Test Plan

### Intentionally Vulnerable Application

A minimal Flask application with a SQL injection vulnerability:

```python
# target/vulnerable_app/app.py
@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]
    # VULNERABLE: SQL injection
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    result = db.execute(query)
    ...
```

### E2E Flow

```
1. Red Agent attacks vulnerable Flask app
   → Discovers SQL injection in /login endpoint
   → VulnerabilityFinding created

2. LLM generates RemediationProposal
   → Parameterized query fix
   → Affected file: app.py
   → Patch: replace f-string with parameterized query

3. RemediationPolicy validates proposal
   → File path in allowed paths
   → Patch size within limits
   → No forbidden operations

4. CloneManager creates isolated clone
   → Docker container from Flask app image
   → Isolated network
   → No production secrets

5. CloneRemediationExecutor applies fix
   → Snapshots clone (v1)
   → Applies patch to clone/app.py
   → Builds Flask app in clone
   → Runs pytest in clone

6. VulnerabilityRetestOrchestrator executes retest
   → Red Agent attacks remediated clone
   → Original SQL injection blocked
   → Variant: different injection payloads → blocked
   → Regression: app health check passes

7. RemediationOutcome = VERIFIED

8. CloneManager cleans up clone
```

---

## Backward Compatibility Plan

### Branch 1 Preservation

| Concern | Mitigation |
| :--- | :--- |
| State machine changes | Only ADD new states; existing transitions UNCHANGED |
| `REMEDIATING` state reuse | Branch 2 guards are separate from Branch 1 guards |
| `db/models.py` changes | Only APPEND new models; existing models UNCHANGED |
| `domain/exceptions.py` | Only APPEND new rejection codes; existing codes UNCHANGED |
| `agents/red/context.py` | Only ADD `vulnerability_findings` field; existing logic UNCHANGED |
| Existing tests | No test files modified; all 263 existing tests pass unchanged |

### Migration Safety

- New Alembic migration `002_app_remediation` only creates NEW tables
- No ALTER TABLE on existing tables
- No DROP TABLE
- Rollback (downgrade) drops only new tables
- Zero risk to Branch 1 data

### Import Safety

- New package `remediation/` is independent
- Existing packages do NOT import from `remediation/`
- `remediation/` imports FROM existing packages (one-way dependency)

---

## Security Boundaries

| Boundary | Enforcement | LLM Cannot Bypass |
| :--- | :--- | :--- |
| Production READ-ONLY | `TargetAuthorizationValidator` | Cannot write to production targets |
| Clone isolation | Docker network + resource limits | Cannot access production network from clone |
| Patch validation | `RemediationPolicyValidator` | Cannot modify files outside allowed paths |
| Execution boundary | `SimulationAdapter` → `PolicyEngine` → `SignedBlueprint` | Cannot execute arbitrary commands |
| Budget enforcement | `RemediationBudget` (Python) | Cannot modify budget limits |
| State transitions | `ExerciseStateMachine` (Python) | Cannot directly control state machine |
| Tenant isolation | `organization_id` on all queries | Cannot access cross-tenant data |
| Audit trail | `AuditLog` for every operation | Cannot hide operations |

---

## Implementation Phases & Effort

| Phase | Description | New Files | Modified Files | Tests | Effort |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **1** | Domain models, exceptions, policy | 5 | 0 | 27 | ~2 days |
| **2** | Database models, migration | 0 | 2 | 0 | ~0.5 days |
| **3** | Clone management | 1 | 0 | 5 | ~2 days |
| **4** | Remediation executor | 1 | 0 | 10 | ~2 days |
| **5** | Red retest | 1 | 0 | 8 | ~2 days |
| **6** | Main orchestrator | 1 | 0 | 10 | ~2 days |
| **7** | LLM prompts | 1 | 0 | 0 | ~1 day |
| **8** | State machine extension | 0 | 1 | 14 | ~1 day |
| **9** | Exceptions & security codes | 0 | 1 | 5 | ~0.5 days |
| **10** | Context builder extension | 0 | 1 | 3 | ~0.5 days |
| **11** | E2E test with vulnerable app | 1 | 0 | 1 | ~2 days |
| **TOTAL** | | **11** | **5** | **83** | **~15 days** |

---

## Risks & Unresolved Architectural Questions

| Risk | Severity | Mitigation | Status |
| :--- | :--- | :--- | :--- |
| Docker-based clone management complexity | MEDIUM | Start with simple `docker run` + `docker commit`; defer advanced snapshotting | OPEN |
| LLM proposal quality for real code fixes | MEDIUM | Use structured schema + policy validation; always verify with build/test | OPEN |
| Intentionally vulnerable test app maintenance | LOW | Use established DVWA or minimal custom Flask app | OPEN |
| Build/test execution time in clones | MEDIUM | Set aggressive timeouts; pre-build base images | OPEN |
| Real-world application cloning fidelity | HIGH | Start with Dockerized apps only (not local filesystem); pin exact images | OPEN |
| `REMEDIATING` state shared between Branch 1 and 2 | LOW | Guard logic differentiates by `retest_result` type (`RetestResult` vs `VulnerabilityRetestResult`) | OPEN |
| Secret injection in clones | MEDIUM | Use environment variables with synthetic test values; never mount production secret volumes | OPEN |
| Rollback reliability with complex applications | MEDIUM | Docker commit/restore is atomic; filesystem-only patches are trivially rollbackable | OPEN |

---

## Summary

1. **Current Branch 1 status**: COMPLETED. 263 tests passing. Full detection gap → Blue Agent → Sigma rule → Retest → VERIFIED loop.
2. **Current Branch 2 status**: DESIGN COMPLETE. NOT IMPLEMENTED. Zero existing code.
3. **Estimated implementation effort**: ~15 working days (83 new tests, 11 new files, 5 modified files).
4. **Smallest viable Branch 2 milestone**: SQL injection in Flask app → parameterized query fix → clone → retest → VERIFIED.
5. **Risks and unresolved questions**: Docker clone complexity, LLM proposal quality for real fixes, application cloning fidelity. All mitigated by starting with Dockerized, pinned-image applications and structured proposal validation.
