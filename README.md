# SentinelForge

Evidence-Driven Autonomous Security Validation Platform.

## Project Status

| Phase | Status | Description |
|-------|--------|-------------|
| **Phase 1** | ✅ COMPLETE | Core domain models, Policy Engine, HMAC signing, replay protection, state machine, security tests |
| **Phase 2** | ✅ COMPLETE | Simulation Worker, Docker SDK integration, hardened target container, timeout enforcement, bounded output, execution evidence |
| **Phase 3** | 🔲 PLANNED | Falco eBPF telemetry collection, Sigma rule evaluation |
| **Phase 4** | 🔲 FUTURE | LLM Planner/Analyst agents, remediation engine |
| **Phase 5** | 🔲 FUTURE | React dashboard, production deployment |

## Architecture

```
ActionIR → Policy Engine → SignedBlueprint → Simulation Worker → Target Container → Execution Result
```

### Security Boundaries

| Component | Trust Level | Notes |
|-----------|-------------|-------|
| Policy Engine | Deterministic authorization boundary | No LLM. Exact-match allowlists. |
| HMAC Signer | Integrity/authenticity | Does NOT provide authorization alone |
| Simulation Worker | Conditionally trusted, highly privileged | Has Docker socket access (MVP tradeoff) |
| Target Container | Hostile execution environment | cap_drop=ALL, read_only, no-new-privileges, non-root |
| Docker Socket | HIGH-PRIVILEGE MVP tradeoff | Application-level wrapper is NOT a host security boundary |

### Target Container Hardening

- Ubuntu 22.04
- Non-root `labuser`
- `cap_drop: ["ALL"]`
- `security_opt: ["no-new-privileges:true"]`
- `read_only: true`
- `tmpfs: ["/tmp"]`
- No Docker socket mounted
- No curl, wget, nc, ssh, compilers

### Timeout Strategy

Commands are wrapped with `/usr/bin/timeout <seconds>` inside the target container. This avoids introducing a secondary privileged execution pathway in the Worker. GNU timeout sends SIGTERM on expiry (exit code 124).

## Repository Structure

```
backend/
├── requirements.txt
├── src/sentinelforge/
│   ├── config.py
│   ├── db/
│   │   ├── models.py          # SQLAlchemy models (Organization, User, Exercise, SimulationResult, AuditLog, etc.)
│   │   └── session.py
│   ├── domain/
│   │   ├── action_ir.py       # ActionIR Pydantic schema
│   │   ├── blueprint.py       # SignedBlueprint schema
│   │   ├── exceptions.py      # SecurityRejection + SecurityRejectionCode
│   │   ├── simulation.py      # SimulationRequest, SimulationExecution
│   │   └── state_machine.py   # Exercise state transitions
│   ├── policy/
│   │   ├── allowlists.py      # Exact-match bash command allowlist
│   │   ├── engine.py          # Deterministic Policy Engine
│   │   └── signing.py         # HMAC-SHA256 BlueprintSigner
│   └── simulation/
│       ├── docker_client.py   # SafeDockerClient (restricted Docker SDK wrapper)
│       ├── replay.py          # SimulationRepository (atomic blueprint claim)
│       └── worker.py          # SimulationWorker orchestrator
├── tests/
│   ├── test_security.py       # Phase 1 unit tests (8 tests)
│   └── integration/
│       ├── test_simulation.py # Phase 2 simulation tests (12 tests)
│       └── test_target.py     # Phase 2 target hardening tests (7 tests)
target/
├── Dockerfile
└── docker-compose.yml
```

## Running Tests

```bash
cd backend
$env:PYTHONPATH="src"   # PowerShell
python -m pytest tests/ -v
```

## Running the Target Container

```bash
cd target
docker compose up -d --build
```

## Test Results (Phase 1 + Phase 2)

```
27 passed, 0 failed, 0 skipped
```

