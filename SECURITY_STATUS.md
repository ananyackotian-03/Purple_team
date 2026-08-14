# Security Status

## Key Defenses Active
1. **Target Sandbox**: The `sentinelforge-target` container operates with `cap_drop=ALL`, `no-new-privileges=true`, `read_only=true`, and non-root `labuser` (enforced via Dockerfile `USER labuser` directive).
2. **Experiment Safety Boundary**: Evaluates scenario risk levels, mandatory approval gates, authorized target memberships, and delegates to low-level exact-match bash allowlisting.
3. **No Arbitrary Commands**: The Simulation Worker cannot be coerced to run secondary privileged wrapper commands (timeout is handled natively by GNU coreutils inside the target).
4. **Replay Protection**: The PostgreSQL database guarantees that a single blueprint cannot be executed twice (`SimulationResult.blueprint_id` UNIQUE constraint).
5. **Memory & Output Protection**: Worker limits output streams to 64KB (`max_stdout_bytes`), preventing stdout/stderr denial of service. Collector bounds raw telemetry lines to 64KB and fields to 4KB.
6. **Telemetry Sanitization & Canonicalization**: Raw telemetry is treated as untrusted input — null bytes are stripped, control characters removed, and Unicode NFC-normalized prior to evaluation.

## Security Invariant: Unicode NFC vs. Homoglyph Defense
- `TelemetryNormalizer` performs `unicodedata.normalize('NFC', value)` to standardize combined Unicode codepoints.
- **NFC normalization does NOT protect against cross-script homoglyph attacks** (e.g. Latin 'a' `U+0061` vs Cyrillic 'а' `U+0430` remain distinct codepoints under NFC).
- Security authorization relies strictly on deterministic controls: exact-match binary paths, controlled argument lists, and hardcoded allowlists.

## Verification Status — VERIFIED
- **Target Sandbox Controls (`--read-only`, `cap_drop=ALL`, `no-new-privileges`, `labuser`, `tmpfs /tmp`)**: **VERIFIED** with real Docker daemon execution.
- **Experiment Safety Boundary & Policy Engine**: **VERIFIED** (15 unit tests + 4 adversarial tests PASSING).
- **Replay Protection & Claim Atomicity**: **VERIFIED** (3 multithreaded concurrency tests PASSING with real database).
- **Red/Blue Closed-Loop & State Machine**: **VERIFIED** with real Docker execution (`test_full_closed_loop_e2e_remediation` PASSED).
- **Security Adversarial Suite**: **VERIFIED** (11/11 adversarial attack vector tests PASSING).
- **Container Runtime Security**: **VERIFIED** (7/7 target hardening tests PASSING with real Docker).
- **Simulation Worker Security**: **VERIFIED** (12/12 simulation tests PASSING with real Docker).

## Limitations & Trade-offs
1. **Docker Socket MVP**: `/var/run/docker.sock` is mounted to the Simulation Worker. A complete breach of the Worker container would grant host-level privileges.
2. **Stream Demuxing**: Target standard streams are interleaved into stdout due to current Docker SDK limitations.
3. **Correlation Unreliability**: Correlation fields use `NULL` when mapping evidence to exercises cannot be established deterministically, preventing false correlations.
