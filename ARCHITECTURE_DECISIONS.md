# Architecture Decisions

## ADR-001: Auditd Replaced by Falco eBPF Sidecar
**Context**: The Linux audit subsystem is not namespaced. Auditd cannot run inside a container with `cap_drop=ALL`.
**Decision**: Use Falco with eBPF as a sidecar container for syscall-level telemetry.
**Status**: Decision made. Falco implementation deferred to Phase 3.

## ADR-002: Deterministic Policy Engine (No LLM)
**Context**: Security authorization must be deterministic and auditable.
**Decision**: The Policy Engine uses exact string equality matching for bash commands. No regex, substring, wildcard, or pattern matching. LLMs are never in the authorization path.
**Rationale**: Any pattern-matching approach enables injection bypasses.

## ADR-003: HMAC Provides Integrity, Not Authorization
**Context**: HMAC-SHA256 signs the complete security-relevant blueprint payload.
**Decision**: HMAC proves that a blueprint was not tampered with and was issued by a trusted signer. It does NOT by itself authorize execution. The Policy Engine is the authorization boundary.

## ADR-004: Docker Socket is an MVP Trust Boundary
**Context**: The Simulation Worker requires Docker socket access to execute commands inside the target container.
**Decision**: For MVP, `/var/run/docker.sock` is mounted to the Worker container. This gives the Worker effective root-level host access.
**Documented Risk**: A fully compromised Worker could bypass the application-level wrapper and control Docker arbitrarily. The `SafeDockerClient` wrapper prevents unauthorized operations through the *normal application execution path* only.
**Future**: Phase 2+ should evaluate a restricted Docker socket proxy.

## ADR-005: Docker Exec Termination via GNU timeout
**Context**: The Docker Engine API does not provide a native mechanism to terminate exec sessions by ID. The initial approach of sending `kill -9 <PID>` from the Worker was rejected because it creates a second arbitrary privileged execution pathway that bypasses the Policy Engine.
**Decision**: Commands are wrapped with `/usr/bin/timeout <seconds>` inside the target container before execution. GNU timeout sends SIGTERM on expiry and exits with code 124.
**Rationale**: Termination happens entirely within the target container's security context. No secondary Worker-side command execution is needed. The timeout wrapper is injected only by trusted Worker code — the ActionIR/blueprint cannot supply arbitrary timeout executables or arguments.

## ADR-006: Stream Demuxing Limitation
**Context**: Docker SDK's `exec_start(stream=True)` without `demux=True` interleaves stdout and stderr into a single byte stream.
**Decision**: For MVP, all interleaved output is captured as "stdout" in `SimulationExecution`. Separate stderr tracking is structurally present but will receive empty values.
**Future**: Switch to `demux=True` or use `exec_start(detach=False, stream=True, demux=True)` when the Docker SDK version supports reliable demuxed streaming.

## ADR-007: Replay Protection via PostgreSQL Unique Constraint
**Context**: Blueprint replay must be prevented durably across Worker restarts.
**Decision**: `SimulationResult.blueprint_id` has a `UNIQUE` constraint. The `SimulationRepository.claim_blueprint()` method performs an atomic INSERT. If `IntegrityError` occurs, the blueprint has already been claimed → `REPLAY_DETECTED`.
**Rationale**: The database is the final authority. No in-memory sets, Redis, or application-only checks are relied upon for the replay guarantee.

## ADR-008: Bounded Output Collection
**Context**: A malicious or misconfigured command could produce unlimited output, causing memory exhaustion.
**Decision**: Output is bounded during streaming. `MAX_STDOUT_BYTES = 64KB`. When the accumulated buffer exceeds this limit, remaining chunks are discarded and the result is marked `truncated = True`. Memory never grows unbounded.
