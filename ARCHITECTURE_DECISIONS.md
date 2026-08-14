# Architecture Decisions

## ADR-001: Auditd Replaced by Falco eBPF Sidecar
**Context**: The Linux audit subsystem is not namespaced. Auditd cannot run inside a container with `cap_drop=ALL`.
**Decision**: Use Falco with eBPF as a sidecar container for syscall-level telemetry.
**Status**: Decision made. Falco configuration defined in Phase 3.

## ADR-002: Policy Engine as Experiment Safety / Authorization Boundary
**Context**: Security authorization must be deterministic and auditable. AI creativity must be contained without restricting adversarial scenarios to static lists.
**Decision**: The Policy Engine reframes static allowlisting into an Experiment Safety / Authorization Boundary (`ExperimentSafetyBoundary`). Higher-level authorization evaluates targets, user identities, risk levels, and human approval constraints. Low-level process execution retains exact string matching for bash commands as a low-level safety invariant.
**Rationale**: Deterministic safety checks prevent prompt injection or LLM hallucination from exceeding containment, while allowing the Red Agent to generate novel adversarial scenarios above the boundary.

## ADR-003: HMAC Provides Integrity, Not Authorization
**Context**: HMAC-SHA256 signs the complete security-relevant blueprint payload.
**Decision**: HMAC proves that a blueprint was not tampered with and was issued by a trusted signer. It does NOT by itself authorize execution. The Policy Engine / Safety Boundary is the authorization boundary.

## ADR-004: Docker Socket is an MVP Trust Boundary
**Context**: The Simulation Worker requires Docker socket access to execute commands inside the target container.
**Decision**: For MVP, `/var/run/docker.sock` is mounted to the Worker container. This gives the Worker effective root-level host access.
**Documented Risk**: A fully compromised Worker could bypass the application-level wrapper and control Docker arbitrarily. The `SafeDockerClient` wrapper prevents unauthorized operations through the *normal application execution path* only.
**Future**: Phase 2+ should evaluate a restricted Docker socket proxy or VM isolation.

## ADR-005: Docker Exec Termination via GNU timeout
**Context**: The Docker Engine API does not provide a native mechanism to terminate exec sessions by ID. The initial approach of sending `kill -9 <PID>` from the Worker was rejected because it creates a second arbitrary privileged execution pathway that bypasses the Policy Engine.
**Decision**: Commands are wrapped with `/usr/bin/timeout <seconds>` inside the target container before execution. GNU timeout sends SIGTERM on expiry and exits with code 124.
**Rationale**: Termination happens entirely within the target container's security context. No secondary Worker-side command execution is needed.

## ADR-006: Stream Demuxing Limitation
**Context**: Docker SDK's `exec_start(stream=True)` without `demux=True` interleaves stdout and stderr into a single byte stream.
**Decision**: For MVP, all interleaved output is captured as "stdout" in `SimulationExecution`.

## ADR-007: Replay Protection via PostgreSQL Unique Constraint
**Context**: Blueprint replay must be prevented durably across Worker restarts.
**Decision**: `SimulationResult.blueprint_id` has a `UNIQUE` constraint. The `SimulationRepository.claim_blueprint()` method performs an atomic INSERT. If `IntegrityError` occurs, the blueprint has already been claimed → `REPLAY_DETECTED`.

## ADR-008: Bounded Output Collection
**Context**: A malicious or misconfigured command could produce unlimited output, causing memory exhaustion.
**Decision**: Output is bounded during streaming. `MAX_STDOUT_BYTES = 64KB`. When the accumulated buffer exceeds this limit, remaining chunks are discarded and the result is marked `truncated = True`.

## ADR-009: Pluggable Simulation Adapters (`SimulationAdapter`)
**Context**: SentinelForge must scale to non-Docker targets (Web/API, DB, Windows, Cloud labs) without altering control-plane safety logic.
**Decision**: Introduce `SimulationAdapter` abstract interface. `ContainerLinuxAdapter` wraps the existing `SafeDockerClient` implementation.
**Rationale**: Keeps control plane decoupled from specific lab environments.

## ADR-010: Telemetry Is Evidence, Never Instructions
**Context**: Telemetry generated during adversarial execution passes through collector and detection engines.
**Decision**: Telemetry input is untrusted data. Every field is sanitized, null-stripped, NFC-normalized, and bounded in length. Telemetry strings are never evaluated or interpreted as instructions by agents.

## ADR-011: Sigma Matcher Fallback Engine
**Context**: External `pySigma` and `sigma-rule-matcher` AST translation libraries may not be available or fully compatible in all execution environments.
**Decision**: `SigmaEngine` integrates `pySigma` when available and falls back to a built-in deterministic field-matcher.
**Rationale**: Ensures telemetry detection remains reliable without hard external dependency blocks.

## ADR-012: Formal Execution Constraints in ActionIR Schema
**Context**: Execution limits (`max_execution_seconds`, `max_stdout_bytes`) were passed dynamically from `RedAgentPlanner` to `ActionIR` without formal Pydantic schema declarations.
**Decision**: Formally declare `max_execution_seconds` (default: 30s, ge: 1, le: 300) and `max_stdout_bytes` (default: 64KB, ge: 1024, le: 1MB) as explicit `ActionIR` model attributes.
**Rationale**: Guarantees boundary parameters are validated, typed, and signed deterministically.

## ADR-013: Unicode NFC Canonicalization & Homoglyph Security Invariant
**Context**: Untrusted telemetry strings require sanitization. Previous documentation incorrectly suggested NFC normalization prevents homoglyph attacks.
**Decision**: `TelemetryNormalizer` applies `unicodedata.normalize('NFC', value)` to canonicalize combined Unicode codepoints.
**Security Invariant**: NFC normalization standardizes string encoding but **does NOT convert cross-script homoglyphs/confusables** (e.g. Latin 'a' `U+0061` vs Cyrillic 'а' `U+0430`). Security authorization relies strictly on exact-match allowlists, canonical binary paths, and structured schemas.

## ADR-014: Durable Detection Gap & Policy Decision Persistence
**Context**: Telemetry detection gaps and safety boundary decisions must establish an auditable evidence chain for remediation and retesting.
**Decision**: Introduce `DetectionGapRecord` (table `detection_gaps`) and wire `PolicyDecisionRecord` (table `policy_decisions`) persistence in the database with Alembic migration version `001_reconciliation_schema_update`.
**Rationale**: Ensures gap analysis, rule generation, and verification history persist across worker and service restarts.

