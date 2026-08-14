# Security Status

## Key Defenses Active
1. **Target Sandbox**: The `sentinelforge-target` container operates with `cap_drop=ALL`, `no-new-privileges=true`, `read_only=true`, and non-root `labuser`.
2. **Experiment Safety Boundary**: Evaluates scenario risk levels, mandatory approval gates, authorized target memberships, and delegates to low-level exact-match bash allowlisting.
3. **No Arbitrary Commands**: The Simulation Worker cannot be coerced to run secondary privileged wrapper commands (timeout is handled natively by GNU coreutils inside the target).
4. **Replay Protection**: The PostgreSQL database guarantees that a single blueprint cannot be executed twice.
5. **Memory Protection**: Worker limits output streams to 64KB, preventing stdout/stderr denial of service. Collector bounds raw telemetry lines to 16KB and fields to 4KB.
6. **Telemetry Sanitization**: Raw telemetry is treated as untrusted input — null bytes are stripped, control characters removed, and Unicode NFC-normalized prior to evaluation.

## Phase 6 Security Verification Status
- **Target Sandbox Controls (`--read-only`, `cap_drop=ALL`, `no-new-privileges`, `labuser`, `tmpfs /tmp`)**: **VERIFIED IN CODE & CI WORKFLOW**, **BLOCKED BY ENVIRONMENT LOCALLY** (requires live Docker daemon to execute container runtime checks).
- **Experiment Safety Boundary & Policy Engine**: **VERIFIED** (12 unit tests + 4 adversarial tests PASSING).
- **Replay Protection & Claim Atomicity**: **VERIFIED** (3 multithreaded concurrency tests PASSING).
- **Red/Blue Closed-Loop & State Machine**: **VERIFIED IN UNIT & MOCK** (21 Blue Agent tests PASSING), **BLOCKED BY ENVIRONMENT LOCALLY** for live Docker execution.
- **Security Adversarial Suite**: **VERIFIED** (11/11 adversarial attack vector tests PASSING).

## Limitations & Trade-offs
1. **Docker Socket MVP**: `/var/run/docker.sock` is mounted to the Simulation Worker. A complete breach of the Worker container would grant host-level privileges.
2. **Stream Demuxing**: Target standard streams are interleaved into stdout due to current Docker SDK limitations.
3. **Correlation Unreliability**: Correlation fields use `NULL` when mapping evidence to exercises cannot be established deterministically, preventing false correlations.
4. **Environment Dependency**: Live Linux Docker execution tests require a working Docker daemon (available in GitHub Actions `ubuntu-latest` runner).
