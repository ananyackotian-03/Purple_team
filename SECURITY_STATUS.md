# Security Status

## Key Defenses Active
1. **Target Sandbox**: The `sentinelforge-target` container operates with `cap_drop=ALL`, `no-new-privileges=true`, `read_only=true`, and non-root `labuser`.
2. **Deterministic Allowlist**: The Policy Engine uses exact-match string equality for authorized bash commands.
3. **No Arbitrary Commands**: The Simulation Worker cannot be coerced to run secondary privileged wrapper commands (timeout is handled natively by GNU coreutils inside the target).
4. **Replay Protection**: The PostgreSQL database guarantees that a single blueprint cannot be executed twice.
5. **Memory Protection**: Worker limits output streams to 64KB, preventing stdout/stderr denial of service.

## Limitations & Trade-offs
1. **Docker Socket MVP**: `/var/run/docker.sock` is mounted to the Simulation Worker. A complete breach of the Worker container would grant host-level privileges.
2. **Stream Demuxing**: Target standard streams are interleaved into stdout due to current Docker SDK limitations. Stderr assertions must currently inspect the combined stream.
